//! Pozycje menu ksni (DBusMenu). Menu jest budowane od nowa ze stanu przy każdej zmianie,
//! a ksni sam wysyła hostowi tylko różnice.
//!
//! Wywołania zwrotne dostają `&mut T` w wątku ksni i trzymają jego blokadę: mogą zmienić stan
//! (np. ustawić "busy"), ale wszystko, co czeka, idzie przez `crate::bg`.

use ksni::menu::{CheckmarkItem, RadioGroup, RadioItem, StandardItem, SubMenu};
use ksni::MenuItem;

pub type Menu<T> = Vec<MenuItem<T>>;

/// DBusMenu używa "_" jako znacznika klawisza skrótu; dosłowny trzeba podwoić.
pub fn label(text: &str) -> String {
    text.replace('_', "__")
}

/// Wyszarzony tekst.
pub fn text<T>(t: &str) -> MenuItem<T> {
    StandardItem { label: label(t), enabled: false, ..Default::default() }.into()
}

pub fn button<T>(t: &str, enabled: bool, f: impl Fn(&mut T) + Send + 'static) -> MenuItem<T> {
    StandardItem { label: label(t), enabled, activate: Box::new(f), ..Default::default() }.into()
}

/// Pole wyboru; `f` dostaje nowy stan (odwrotność `checked`).
pub fn check<T>(t: &str, checked: bool, enabled: bool, f: impl Fn(&mut T, bool) + Send + 'static) -> MenuItem<T> {
    CheckmarkItem {
        label: label(t),
        checked,
        enabled,
        activate: Box::new(move |tray: &mut T| f(tray, !checked)),
        ..Default::default()
    }
    .into()
}

pub fn submenu<T>(t: &str, enabled: bool, items: Menu<T>) -> MenuItem<T> {
    SubMenu { label: label(t), enabled, submenu: items, ..Default::default() }.into()
}

pub fn sep<T>() -> MenuItem<T> {
    MenuItem::Separator
}

/// Grupa opcji (label, enabled); `selected` poza zakresem = nic nie zaznaczone.
/// `f` jest wołane tylko przy zmianie wyboru - kliknięcie zaznaczonej opcji nic nie robi.
pub fn radio<T>(
    options: Vec<(String, bool)>,
    selected: usize,
    f: impl Fn(&mut T, usize) + Send + 'static,
) -> MenuItem<T> {
    RadioGroup {
        selected,
        select: Box::new(move |tray: &mut T, i| {
            if i != selected {
                f(tray, i)
            }
        }),
        options: options
            .into_iter()
            .map(|(t, enabled)| RadioItem { label: label(&t), enabled, ..Default::default() })
            .collect(),
    }
    .into()
}

/// Menu jako tekst (tryb --dump): wcięcia = podmenu, [x]/[ ] = pola wyboru, (o)/( ) = opcje,
/// "~" = wyszarzone.
pub fn dump<T>(items: &[MenuItem<T>]) -> String {
    fn show(t: &str) -> String {
        t.replace("__", "\u{1}").replace('_', "").replace('\u{1}', "_")
    }
    fn walk<T>(items: &[MenuItem<T>], depth: usize, out: &mut String) {
        let pad = "    ".repeat(depth);
        for item in items {
            match item {
                MenuItem::Standard(i) => {
                    out.push_str(&format!("{pad}{}{}\n", if i.enabled { "" } else { "~" }, show(&i.label)))
                }
                MenuItem::Checkmark(i) => out.push_str(&format!(
                    "{pad}{}[{}] {}\n",
                    if i.enabled { "" } else { "~" },
                    if i.checked { "x" } else { " " },
                    show(&i.label)
                )),
                MenuItem::SubMenu(i) => {
                    out.push_str(&format!("{pad}{}{} >\n", if i.enabled { "" } else { "~" }, show(&i.label)));
                    walk(&i.submenu, depth + 1, out);
                }
                MenuItem::RadioGroup(g) => {
                    for (n, o) in g.options.iter().enumerate() {
                        out.push_str(&format!(
                            "{pad}{}({}) {}\n",
                            if o.enabled { "" } else { "~" },
                            if n == g.selected { "o" } else { " " },
                            show(&o.label)
                        ));
                    }
                }
                MenuItem::Separator => out.push_str(&format!("{pad}----\n")),
            }
        }
    }
    let mut out = String::new();
    walk(items, 0, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn underscores_are_literal() {
        assert_eq!(label("netbird_wt0"), "netbird__wt0");
    }
}
