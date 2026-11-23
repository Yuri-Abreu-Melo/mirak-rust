#[cfg(feature = "gui")]
use {
    crate::{Cli, report, routinator, security_scan},
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

    let api_text = Label::builder().build();
    api_text.set_markup(
        "NVD API key is optional; official advisories and OSV are queried online",
    );

    let bytes = gtk::glib::Bytes::from(IMAGE_DATA);
    let texture = Texture::from_bytes(&bytes).unwrap();
    let image = Picture::for_paintable(&texture);

    let scrolled_window = ScrolledWindow::builder()
        .height_request(450)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();

    // Buffers
    let api_key_buffer = TextBuffer::builder().build();
    let output_buffer = TextBuffer::builder().build();

    // TextViews
    let api_key_view = TextView::builder()
        .buffer(&api_key_buffer)
        .height_request(30)
        .vexpand(false)
        .hexpand(false)
        .wrap_mode(gtk::WrapMode::Word)
        .margin_start(200)
        .margin_end(200)
        .build();

    let output_text_view = TextView::builder()
        .buffer(&output_buffer)
        .vexpand(true)
        .editable(false)
        .cursor_visible(false)
        .margin_start(10)
        .margin_end(10)
        .margin_top(10)
        .margin_bottom(10)
        .build();

    let hbox = Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .halign(gtk::Align::Center)
        .valign(gtk::Align::Center)
        .spacing(15)
        .width_request(700)
        .vexpand(true)
        .hexpand(false)
        .build();

    let init_btn = Button::builder()
        .label("🚀 Start CVE Triage")
        .sensitive(true)
        .margin_bottom(5)
        .build();

    init_btn.connect_clicked({
        let api_key_buffer = api_key_buffer.clone();
        let output_buffer = output_buffer.clone();
        let output_text_view = output_text_view.clone();

        move |_| {
            output_buffer.set_text("");

            let (start, end) = api_key_buffer.bounds();
            let nvd_key = api_key_buffer.text(&start, &end, false).to_string();

            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();

            let log_ui = {
                let output_buffer = output_buffer.clone();
                let output_text_view = output_text_view.clone();
                move |msg: &str| {
                    // Remove ANSI characters and keep emojis
                    let clean_msg = strip_ansi_escapes(msg);
                    output_buffer.insert(&mut output_buffer.end_iter(), &clean_msg);
                    let mut end = output_buffer.end_iter();
                    output_text_view.scroll_to_iter(&mut end, 0.0, false, 0.0, 0.0);
                }
            };

            fn strip_ansi_escapes(input: &str) -> String {
                let re = regex::Regex::new(r"\x1b\[[0-9;]*[mK]").unwrap();
                re.replace_all(input, "").to_string()
            }

            log_ui("═══════════════════════════════════════════\n");
            log_ui("🚀 STARTING MIRAK CVE TRIAGE\n");
            log_ui("═══════════════════════════════════════════\n\n");

            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();

                rt.block_on(async {
                    let log = |msg: &str| {
                        let _ = tx.send(msg.to_string());
                    };

                    log("[INFO] Running Routinator-only configuration/permission pre-check\n");
                    log(&routinator::validator::validate_gui());
                    log("[INFO] Routinator pre-check finished; review its messages above. CVE triage also covers Fort.\n\n");
                    log("[INFO] Checking official advisories, identifiable dependencies, and NVD when configured\n\n");

                    let key = (!nvd_key.trim().is_empty()).then_some(nvd_key.as_str());
                    match security_scan::scan(key).await {
                        Ok(scan_result) => {
                            let warning_count = scan_result.warnings.len();
                            for warning in &scan_result.warnings {
                                log(&format!("[WARN] {warning}\n"));
                            }
                            log(&format!(
                                "\n[SUMMARY] {} possible match(es) for supported validators/dependencies\n",
                                scan_result.findings.len()
                            ));
                            if scan_result.findings.is_empty() {
                                log("No possible matches were found in the sources checked; this does not prove that the system is vulnerability-free.\n");
                            } else {
                                for finding in &scan_result.findings {
                                    log(&format!(
                                        "[MATCH] {} | {} {} | {} | {}\n",
                                        finding.id,
                                        finding.product,
                                        finding.version,
                                        finding.severity,
                                        finding.source
                                    ));
                                }
                            }
                            log("\n[INFO] Writing CSV report\n");
                            let mut report_failed = false;
                            match report::make_report(&scan_result.findings) {
                                Ok(Some(path)) => {
                                    log(&format!("[INFO] CSV report written to {}\n", path.display()));
                                }
                                Ok(None) => {
                                    log("[INFO] No CSV report was generated because there were no matches.\n");
                                }
                                Err(error) => {
                                    report_failed = true;
                                    log(&format!("[ERROR] {error}\n"));
                                }
                            }
                            if report_failed {
                                log("[WARN] Triage finished, but the CSV report could not be written.\n");
                            } else if warning_count > 0 {
                                log(&format!(
                                    "[INFO] Triage finished with {warning_count} warning(s); review them before interpreting coverage.\n"
                                ));
                            } else {
                                log("[INFO] Triage finished. Matches are not confirmation of exploitability.\n");
                            }
                        }
                        Err(error) => log(&format!("[ERROR] {error}\n")),
                    }
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
    image.set_height_request(80);
    image.set_width_request(80);

    hbox.append(&image);
    hbox.append(&api_text);
    hbox.append(&api_key_view);
    hbox.append(&init_btn);
    hbox.append(&scrolled_window);

    scrolled_window.set_child(Some(&output_text_view));

    let window = ApplicationWindow::builder()
        .application(app)
        .title("MIRAK - Security Scanner")
        .child(&hbox)
        .default_height(900)
        .default_width(850)
        .build();

    window.present();
}
