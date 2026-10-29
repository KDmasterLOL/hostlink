use super::*;

#[test]
fn exact_xml_comparison_rejects_changed_actions_identity_and_settings() {
    let xml = r#"<Task xmlns="urn:task" version="1.2"><Principal SID="S-1-5-21"/><Exec><Command>C:\Agent &amp; (test)\agent.exe</Command><Arguments>run --config="a b"</Arguments></Exec><Settings><RunLevel>LeastPrivilege</RunLevel></Settings></Task>"#;
    assert!(equal(xml, &xml.replace("><", ">\n  <")).unwrap());
    for changed in [
        xml.replace("S-1-5-21", "S-1-5-18"),
        xml.replace("agent.exe", "foreign.exe"),
        xml.replace("a b", "a c"),
        xml.replace("LeastPrivilege", "HighestAvailable"),
        xml.replace("urn:task", "urn:foreign"),
        xml.replace("</Exec>", "<Command>foreign.exe</Command></Exec>"),
        xml.replace("</Task>", "<Triggers/></Task>"),
        xml.replace(" version=\"1.2\"", ""),
    ] {
        assert!(!equal(xml, &changed).unwrap(), "accepted {changed}");
    }
    assert!(equal(xml, "<malformed>").is_err());
}

#[test]
fn xml_escaping_preserves_paths_and_rejects_controls() {
    let value = "C:\\Агент & (тест)\\a<'\".exe";
    let xml = format!("<Command>{}</Command>", escape(value).unwrap());
    let parsed = roxmltree::Document::parse(&xml).unwrap();
    assert_eq!(parsed.root_element().text(), Some(value));
    for value in ["a\0b", "a\nb", "a\rb", "a\tb"] {
        assert!(escape(value).is_err());
    }
}
