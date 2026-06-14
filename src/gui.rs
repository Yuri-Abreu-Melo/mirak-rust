#[cfg(feature = "gui")]
use {
    crate::{Cli, cpe, nvd, report, routinator},
    gtk::{
        Application, ApplicationWindow, Box, Button, Label, ScrolledWindow, TextBuffer, TextView,
        glib, prelude::*,
    }, std::{cell::RefCell, rc::Rc},
};

#[cfg(feature = "gui")]
pub fn check_gui(cli: &Cli) -> bool {
    cli.gui
}

#[cfg(feature = "gui")]
pub fn gui() -> glib::ExitCode {
    const APP_ID: &str = "org.ime.mirak";
    let app = Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    app.run_with_args(&[""])
}

#[cfg(feature = "gui")]
pub fn build_ui(app: &Application) {
    let api_text = Label::builder().label("Paste api key").build();

    let scrolled_window = ScrolledWindow::builder()
        .height_request(170)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();

    //Buffers
    let api_key_buffer = TextBuffer::builder().build();
    let output_buffer = TextBuffer::builder().build();

    // TextViews
    let api_key_view = TextView::builder()
        .buffer(&api_key_buffer)
        .height_request(20)
        .vexpand(true)
        .build();
    let output_text_view = TextView::builder()
        .buffer(&output_buffer)
        .vexpand(true)
        .editable(false)
        .cursor_visible(false)
        .build();

    let hbox = Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .halign(gtk::Align::Center)
        .valign(gtk::Align::Center)
        .spacing(25)
        .width_request(600)
        .vexpand(true)
        .build();

    let init_btn = Button::builder().label("Check system").build();

    init_btn.connect_clicked({
        let api_key_buffer = api_key_buffer.clone();
        let output_buffer = output_buffer.clone();
        let output_text_view = output_text_view.clone();

        move |_| {
            let (start, end) = api_key_buffer.bounds();
            let nvd_key = api_key_buffer.text(&start, &end, false).to_string();

            // Canal Tokio para comunicação entre threads
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();

            // Função de log na UI (thread principal)
            let log_ui = {
                let output_buffer = output_buffer.clone();
                let output_text_view = output_text_view.clone();
                move |msg: &str| {
                    output_buffer.insert(&mut output_buffer.end_iter(), msg);
                    let mut end = output_buffer.end_iter();
                    output_text_view.scroll_to_iter(&mut end, 0.0, false, 0.0, 0.0);
                }
            };

            log_ui("[INFO] - Iniciando processo de validação...\n");

            // Thread de trabalho separada
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();

                rt.block_on(async {
                    let log = |msg: &str| {
                        let _ = tx.send(msg.to_string());
                    };

                    log("[INFO] - Iniciando processo de validação dos dados do Routinator\n");
                    log(&routinator::validator::validate_gui());
                    log("[INFO] - Processo de validação dos dados do Routinator finalizado com sucesso\n");
                    log("[INFO] - Iniciando validação dos binários do sistema operacional\n");
                    
                    let cpes = cpe::builder::build_cpe_gui();
                    let nvd_result = nvd::check_gui::check_gui(cpes, nvd_key, tx.clone()).await;
                    
                    log("[INFO] - Processando relatório de vulnerabilidades\n");
                    report::make_report(nvd_result);
                    log("[INFO] - ✅ Verificação concluída!\n");
                });
            });

          let log_ui = Rc::new(RefCell::new(log_ui));
let rx = Rc::new(RefCell::new(rx));

glib::idle_add_local(move || {
    let mut rx = rx.borrow_mut();
    
    // Processa várias mensagens de uma vez, mas limita para não bloquear
    for _ in 0..10 {
        match rx.try_recv() {
            Ok(msg) => {
                (log_ui.borrow())(&msg);
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return glib::ControlFlow::Break,
        }
    }
    
    glib::ControlFlow::Continue
});        }
    });

    hbox.append(&api_text);
    hbox.append(&api_key_view);
    hbox.append(&init_btn);
    hbox.append(&scrolled_window);

    scrolled_window.set_child(Some(&output_text_view));

    let window = ApplicationWindow::builder()
        .application(app)
        .title("Mirak")
        .child(&hbox)
        .default_height(600)
        .default_width(800)
        .build();

    window.present();
}
