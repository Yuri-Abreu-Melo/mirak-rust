#[cfg(feature = "gui")]
use {
    crate::{Cli, cpe, nvd, report, routinator},
    gtk::{
        Application, ApplicationWindow, Box, Button, Label, Picture, ScrolledWindow, TextBuffer,
        TextView, gdk::Texture, glib, prelude::*,
    },
    std::{cell::RefCell, rc::Rc},
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
    const IMAGE_DATA: &[u8] = include_bytes!("../assets/ime-crest.png");
    let api_text = Label::builder()
        .label("Insert here your NVD key in order to check the system")
        .build();
    let bytes = gtk::glib::Bytes::from(IMAGE_DATA);
    let texture = Texture::from_bytes(&bytes).unwrap();
    let image = Picture::for_paintable(&texture);

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
        .vexpand(false)
        .hexpand(false)
        .wrap_mode(gtk::WrapMode::Word)
        .margin_start(250)
        .margin_end(250)
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
        .hexpand(false)
        .build();

    let init_btn = Button::builder().label("Check system").build();

    init_btn.connect_clicked({
        let api_key_buffer = api_key_buffer.clone();
        let output_buffer = output_buffer.clone();
        let output_text_view = output_text_view.clone();

        move |_| {
            let (start, end) = api_key_buffer.bounds();
            let nvd_key = api_key_buffer.text(&start, &end, false).to_string();

            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();

            let log_ui = {
                let output_buffer = output_buffer.clone();
                let output_text_view = output_text_view.clone();
                move |msg: &str| {
                    output_buffer.insert(&mut output_buffer.end_iter(), msg);
                    let mut end = output_buffer.end_iter();
                    output_text_view.scroll_to_iter(&mut end, 0.0, false, 0.0, 0.0);
                }
            };

            log_ui("[INFO] - Initializing validation process...\n");

            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();

                rt.block_on(async {
                    let log = |msg: &str| {
                        let _ = tx.send(msg.to_string());
                    };

                    log("[INFO] - Initializing validation of Routinator data\n");
                    log(&routinator::validator::validate_gui());
                    log("[INFO] - Validation Routinator process finished\n");
                    log("[INFO] - Initializing SO binaries validation\n");

                    let cpes = cpe::builder::build_cpe_gui();
                    let nvd_result = nvd::check_gui::check_gui(cpes, nvd_key, tx.clone()).await;

                    log("[INFO] - Processing vulnerabilities report\n");
                    report::make_report(nvd_result);
                    log("[INFO] - ✅ Validation finished!\n");
                });
            });

            let log_ui = Rc::new(RefCell::new(log_ui));
            let rx = Rc::new(RefCell::new(rx));

            glib::timeout_add_local(std::time::Duration::from_millis(50), move || {
                let mut rx = rx.borrow_mut();
                let mut count = 0;

                while let Ok(msg) = rx.try_recv() {
                    (log_ui.borrow())(&msg);
                    count += 1;
                    if count >= 20 {
                        break;
                    }
                }

                if rx.is_closed() && count == 0 {
                    glib::ControlFlow::Break
                } else {
                    glib::ControlFlow::Continue
                }
            });
        }
    });

    image.set_valign(gtk::Align::Center);
    image.set_halign(gtk::Align::Center);
    image.set_content_fit(gtk::ContentFit::Contain);
    image.set_margin_top(20);
    hbox.append(&image);
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
