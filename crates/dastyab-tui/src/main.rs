//! DastYab TUI (ratatui).
//!
//! A terminal dashboard that shares the core library. It shows a live,
//! friendly overview of profiles, tokens, config history, clean IPs, recently
//! generated share links, automatic updates, and the current application state.
//!
//! * `q` / `Esc` — quit
//! * `Tab` / `1..3` — cycle between the Overview / Profiles / Share-link panels
//! * `u` — check & apply update from GitHub Releases now
//! * `r` — restart TUI into newly installed update (when ready)

use std::io::IsTerminal as _;
use std::sync::mpsc;

use dastyab_core::selfupdate::{
    cleanup_stale_old_binary, ensure_updated_with_swap_for, should_auto_check, BinaryKind,
    UpdateOutcome,
};
use dastyab_core::store::profiles::{list_profiles, load_profile, migrate_legacy};

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

const GOLD: Color = Color::Rgb(212, 175, 55);
const GOLD_DIM: Color = Color::Rgb(150, 120, 40);
const GREEN: Color = Color::Rgb(130, 220, 145);
const TEXT: Color = Color::Rgb(235, 228, 200);

fn main() -> std::io::Result<()> {
    dastyab_core::tls::install_tls_provider();
    cleanup_stale_old_binary();
    let _ = migrate_legacy();

    // `ratatui::init()` panics with a raw backtrace ("failed to initialize
    // terminal: Os { code: 6 ... }") when stdin is not a terminal, which is
    // what happens under cron, in CI, or when output is piped. A dashboard
    // that needs a tty should say so and exit non-zero, not dump a panic.
    if !std::io::stdin().is_terminal() {
        eprintln!("dastyab-tui: this is an interactive terminal dashboard and needs a tty.");
        eprintln!("Run it directly in your terminal, or use the CLI (`dastyab`) instead.");
        std::process::exit(1);
    }

    let mut terminal = ratatui::init();
    let res = run_app(&mut terminal);
    ratatui::restore();
    match res {
        Ok(Some(exe)) => {
            // Re-launch the newly updated TUI binary after restoring the terminal.
            let _ = std::process::Command::new(exe).status();
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(e) => Err(e),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Overview,
    Profiles,
    Links,
}

struct AutoUpdateUiState {
    checking: bool,
    status: String,
    ready_tag: Option<String>,
    rx: mpsc::Receiver<Result<UpdateOutcome, String>>,
    tx: mpsc::Sender<Result<UpdateOutcome, String>>,
}

impl AutoUpdateUiState {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        let ver = dastyab_core::VERSION;
        Self {
            checking: false,
            status: format!("v{ver} · auto-update ready (press 'u' to check)"),
            ready_tag: None,
            rx,
            tx,
        }
    }

    fn start_check(&mut self, manual: bool) {
        if self.checking {
            return;
        }
        self.checking = true;
        self.status = if manual {
            "Checking GitHub Releases for TUI update…".to_string()
        } else {
            "Background auto-update check running…".to_string()
        };
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = match tokio::runtime::Runtime::new() {
                Ok(rt) => {
                    let fut = ensure_updated_with_swap_for(
                        BinaryKind::Tui,
                        std::time::Duration::from_secs(90),
                    );
                    rt.block_on(fut).map_err(|e| e.brief())
                }
                Err(e) => Err(format!("runtime error: {e}")),
            };
            let _ = tx.send(result);
        });
    }

    fn poll(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            self.checking = false;
            match msg {
                Ok(UpdateOutcome::UpToDate) => {
                    self.status = format!("v{} · up to date", dastyab_core::VERSION);
                }
                Ok(UpdateOutcome::Updated { tag }) => {
                    self.ready_tag = Some(tag.clone());
                    self.status = format!("Update {tag} installed — press 'r' to restart TUI");
                }
                Ok(UpdateOutcome::Staged { tag, path }) => {
                    self.status = format!("Update {tag} staged at {path} (read-only dir)");
                }
                Ok(UpdateOutcome::Failed(err)) => {
                    self.status = format!("Update check failed: {err}");
                }
                Err(err) => {
                    self.status = format!("Update check skipped: {err}");
                }
            }
        }
    }
}

fn run_app(terminal: &mut ratatui::DefaultTerminal) -> std::io::Result<Option<std::path::PathBuf>> {
    let mut tab = Tab::Overview;
    let mut updater = AutoUpdateUiState::new();
    let interval = dastyab_core::selfupdate::INTERACTIVE_CHECK_INTERVAL_SECS;
    if should_auto_check(interval) {
        updater.start_check(false);
    }

    loop {
        updater.poll();

        terminal.draw(|frame| {
            let area = frame.area();
            // Vertical layout: title bar (2), update strip (1), tab strip (1), separator (1), body (rest).
            let constraints = [
                Constraint::Length(2),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(0),
            ];
            let layout = Layout::default().direction(Direction::Vertical);
            let chunks = layout.constraints(constraints).split(area);

            // Title bar
            let title = Paragraph::new(Line::from(vec![
                Span::styled(
                    " DastYab ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(GOLD)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        "  v{} — Cloudflare-Workers VLESS VPN console",
                        dastyab_core::VERSION
                    ),
                    Style::default().fg(GOLD_DIM),
                ),
            ]));
            frame.render_widget(title, chunks[0]);

            // Auto-update status bar
            let upd_style = if updater.ready_tag.is_some() {
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(GOLD_DIM)
            };
            let upd_bar = Paragraph::new(Line::from(Span::styled(
                format!(" {} ", updater.status),
                upd_style,
            )));
            frame.render_widget(upd_bar, chunks[1]);

            // Tab strip
            let tabs = Line::from(vec![
                tab_span(" Overview ", tab == Tab::Overview),
                Span::raw("   "),
                tab_span(" Profiles ", tab == Tab::Profiles),
                Span::raw("   "),
                tab_span(" Share Links ", tab == Tab::Links),
            ]);
            frame.render_widget(Paragraph::new(tabs), chunks[2]);
            frame.render_widget(Block::default().borders(Borders::TOP), chunks[3]);

            match tab {
                Tab::Overview => render_overview(frame, chunks[4], &updater),
                Tab::Profiles => render_profiles(frame, chunks[4]),
                Tab::Links => render_links(frame, chunks[4]),
            }
        })?;

        if crossterm::event::poll(std::time::Duration::from_millis(100))? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                match key.code {
                    crossterm::event::KeyCode::Char('q') | crossterm::event::KeyCode::Esc => {
                        return Ok(None);
                    }
                    crossterm::event::KeyCode::Tab => {
                        tab = match tab {
                            Tab::Overview => Tab::Profiles,
                            Tab::Profiles => Tab::Links,
                            Tab::Links => Tab::Overview,
                        };
                    }
                    crossterm::event::KeyCode::Char('1') => tab = Tab::Overview,
                    crossterm::event::KeyCode::Char('2') => tab = Tab::Profiles,
                    crossterm::event::KeyCode::Char('3') => tab = Tab::Links,
                    crossterm::event::KeyCode::Char('u') => updater.start_check(true),
                    crossterm::event::KeyCode::Char('r') if updater.ready_tag.is_some() => {
                        if let Ok(exe) = std::env::current_exe() {
                            return Ok(Some(exe));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn tab_span(label: &str, active: bool) -> Span<'static> {
    if active {
        Span::styled(
            label.to_string(),
            Style::default()
                .fg(Color::Black)
                .bg(GOLD)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(label.to_string(), Style::default().fg(GOLD_DIM))
    }
}

fn boxed(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GOLD_DIM))
        .title(Span::styled(
            title.to_string(),
            Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
        ))
}

fn render_overview(
    frame: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    updater: &AutoUpdateUiState,
) {
    let profiles = list_profiles();
    let mut lines = vec![Line::from(Span::styled(
        "Welcome to DastYab — your Cloudflare Workers VLESS control plane.",
        Style::default().fg(TEXT),
    ))];

    let mut total_clean = 0usize;
    let mut total_configs = 0usize;
    let mut total_pool_nodes = 0usize;
    for m in &profiles {
        let p = load_profile(&m.id);
        total_clean += p.clean_ips.len();
        total_configs += p.history.len();
        let pool = dastyab_core::artifact::config_store::load_node_store(&m.id);
        total_pool_nodes += pool.nodes.len();
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        format!("Profiles: {}", profiles.len()),
        Style::default().fg(GOLD),
    )));
    lines.push(Line::from(Span::styled(
        format!("Saved configs: {total_configs}   Imported pool: {total_pool_nodes}"),
        Style::default().fg(TEXT),
    )));
    lines.push(Line::from(Span::styled(
        format!("Clean IPs: {total_clean}"),
        Style::default().fg(TEXT),
    )));
    lines.push(Line::from(Span::styled(
        format!("Updates: {}", updater.status),
        Style::default().fg(if updater.ready_tag.is_some() {
            GREEN
        } else {
            TEXT
        }),
    )));
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "Keyboard: 1/2/3 or Tab = panel · u = check/update · r = restart · q/Esc = quit",
        Style::default().fg(GOLD_DIM),
    )));
    lines.push(Line::from(Span::styled(
        "Full tooling (deploy, scan, DNS, routes, backup, audit) lives in the CLI:",
        Style::default().fg(GOLD_DIM),
    )));
    lines.push(Line::from(Span::styled(
        "  dastyab --help",
        Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
    )));

    let widget = Paragraph::new(lines).block(boxed(" Overview "));
    frame.render_widget(widget, area);
}

fn render_profiles(frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
    let profiles = list_profiles();
    let mut lines: Vec<Line> = Vec::new();

    if profiles.is_empty() {
        lines.push(Line::from(Span::styled(
            "No profiles yet — create one with `dastyab profile-create <name>`.",
            Style::default().fg(TEXT),
        )));
    } else {
        for m in &profiles {
            let p = load_profile(&m.id);
            lines.push(Line::from(Span::styled(
                format!("• {} ({})", p.meta.name, p.meta.id),
                Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(Span::styled(
                format!(
                    "    tokens: {}   accounts: {}   configs: {}   clean IPs: {}",
                    p.tokens.len(),
                    p.accounts.len(),
                    p.history.len(),
                    p.clean_ips.len()
                ),
                Style::default().fg(TEXT),
            )));
        }
    }

    let widget = Paragraph::new(lines).block(boxed(" Profiles "));
    frame.render_widget(widget, area);
}

fn render_links(frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
    let profiles = list_profiles();
    let mut lines: Vec<Line> = Vec::new();

    for m in profiles.iter().take(1) {
        let p = load_profile(&m.id);
        let pool = dastyab_core::artifact::config_store::load_node_store(&m.id);
        let recent: Vec<_> = p.history.iter().take(6).collect();
        if recent.is_empty() && pool.nodes.is_empty() {
            lines.push(Line::from(Span::styled(
                "No share links yet — run `dastyab deploy` or `dastyab configs import --path <file.txt>`.",
                Style::default().fg(TEXT),
            )));
        } else {
            for r in recent {
                let tag = if r.clean_ip {
                    "clean-IP"
                } else {
                    "workers.dev"
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("[{}] ", tag),
                        Style::default().fg(if r.clean_ip { GOLD } else { GOLD_DIM }),
                    ),
                    Span::styled(
                        format!(
                            "{} — ",
                            if r.name.is_empty() {
                                &r.address
                            } else {
                                &r.name
                            }
                        ),
                        Style::default().fg(TEXT),
                    ),
                    Span::styled(r.ts.clone(), Style::default().fg(GOLD_DIM)),
                ]));
                if r.link.len() <= 90 {
                    lines.push(Line::from(Span::styled(
                        r.link.clone(),
                        Style::default().fg(GOLD_DIM),
                    )));
                } else {
                    lines.push(Line::from(Span::styled(
                        format!("{}…", &r.link[..90]),
                        Style::default().fg(GOLD_DIM),
                    )));
                }
            }
            for node in pool.nodes.iter().take(6) {
                let src = format!("[{}] ", node.source);
                lines.push(Line::from(vec![
                    Span::styled(src, Style::default().fg(GOLD)),
                    Span::styled(node.alias.clone(), Style::default().fg(TEXT)),
                ]));
                let clipped: String = node.url.chars().take(90).collect();
                lines.push(Line::from(Span::styled(clipped, Style::default().fg(GOLD_DIM))));
            }
        }
    }

    let widget = Paragraph::new(lines).block(boxed(" Recent Share Links "));
    frame.render_widget(widget, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_update_ui_state_transitions_on_messages() {
        let mut st = AutoUpdateUiState::new();
        assert!(!st.checking);
        assert!(st.ready_tag.is_none());

        st.checking = true;
        let msg = Ok(UpdateOutcome::Updated { tag: "v0.9.9".to_string() });
        st.tx.send(msg).unwrap();
        st.poll();
        assert!(!st.checking);
        assert_eq!(st.ready_tag.as_deref(), Some("v0.9.9"));
        assert!(st.status.contains("v0.9.9"));

        st.tx.send(Ok(UpdateOutcome::UpToDate)).unwrap();
        st.poll();
        assert!(st.status.contains("up to date"));
    }
}
