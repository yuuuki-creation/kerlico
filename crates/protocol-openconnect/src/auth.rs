//! `config-auth` XML 认证文档；解析与应答都不做网络 I/O。

use crate::config::Credentials;
use kerlico_core::{Error, Result};
use quick_xml::{
    escape::escape,
    events::{BytesStart, Event},
};

const CLIENT_VERSION: &str = "v9.12";
const MAX_INPUTS: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AuthDocument {
    Form(Form),
    Complete,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Form {
    pub action: String,
    inputs: Vec<Input>,
}

#[derive(Debug, PartialEq, Eq)]
enum Input {
    Text(String),
    Password(String),
    Hidden { name: String, value: String },
}

/// 记录已提交的口令字段；服务端再次索取即表示上一次提交未被接受。
#[derive(Default)]
pub(crate) struct Answered {
    username: bool,
    password: bool,
}

pub(crate) fn init_request(group_access: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <config-auth client=\"vpn\" type=\"init\" aggregate-auth-version=\"2\">\
         <version who=\"vpn\">{CLIENT_VERSION}</version>\
         <device-id>linux-64</device-id>\
         <group-access>{}</group-access></config-auth>",
        escape(group_access)
    )
}

fn attribute(element: &BytesStart<'_>, name: &[u8]) -> Result<Option<String>> {
    let invalid = || Error::Protocol("OpenConnect 认证文档不合法");
    for item in element.attributes() {
        let item = item.map_err(|_| invalid())?;
        if item.key.as_ref() == name {
            return item
                .unescape_value()
                .map(|value| Some(value.into_owned()))
                .map_err(|_| invalid());
        }
    }
    Ok(None)
}

fn valid_action(action: &str) -> bool {
    action.starts_with('/') && action.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_element_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && name.as_bytes()[0].is_ascii_alphabetic()
}

pub(crate) fn parse(xml: &str) -> Result<AuthDocument> {
    let invalid = || Error::Protocol("OpenConnect 认证文档不合法");
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut kind = None;
    let mut action = None;
    let mut inputs = Vec::new();
    loop {
        let element = match reader.read_event().map_err(|_| invalid())? {
            Event::Eof => break,
            Event::Start(element) | Event::Empty(element) => element,
            _ => continue,
        };
        match element.name().as_ref() {
            b"config-auth" => kind = attribute(&element, b"type")?,
            b"form" => action = attribute(&element, b"action")?,
            b"input" => {
                if inputs.len() == MAX_INPUTS {
                    return Err(invalid());
                }
                let name = attribute(&element, b"name")?.ok_or_else(invalid)?;
                let declared = attribute(&element, b"type")?.unwrap_or_default();
                inputs.push(match declared.as_str() {
                    "hidden" => Input::Hidden {
                        name,
                        value: attribute(&element, b"value")?.unwrap_or_default(),
                    },
                    "password" => Input::Password(name),
                    _ => Input::Text(name),
                });
            }
            _ => {}
        }
    }
    match kind.as_deref() {
        Some("complete") => Ok(AuthDocument::Complete),
        Some("auth-request") => {
            let action = action.ok_or_else(invalid)?;
            if !valid_action(&action) {
                return Err(invalid());
            }
            Ok(AuthDocument::Form(Form { action, inputs }))
        }
        _ => Err(invalid()),
    }
}

impl Form {
    /// 生成 `auth-reply`。已答字段被再次索取时返回 `Rejected`，其他索取项（如动态口令）明确不支持。
    pub fn reply(&self, credentials: &Credentials, answered: &mut Answered) -> Result<String> {
        let mut fields = String::new();
        let mut field = |name: &str, value: &str| {
            fields.push_str(&format!("<{name}>{}</{name}>", escape(value)));
        };
        for input in &self.inputs {
            match input {
                Input::Hidden { name, value } => {
                    if !valid_element_name(name) {
                        return Err(Error::Protocol("OpenConnect 认证文档不合法"));
                    }
                    field(name, value);
                }
                Input::Text(name) if name == "username" => {
                    if std::mem::replace(&mut answered.username, true) {
                        return Err(Error::Rejected);
                    }
                    field(name, &credentials.username);
                }
                Input::Password(name) if name == "password" => {
                    if std::mem::replace(&mut answered.password, true) {
                        return Err(Error::Rejected);
                    }
                    field(name, &credentials.password);
                }
                Input::Text(_) | Input::Password(_) => {
                    return Err(Error::Unsupported("OpenConnect 服务端要求未支持的认证字段"));
                }
            }
        }
        Ok(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <config-auth client=\"vpn\" type=\"auth-reply\" aggregate-auth-version=\"2\">\
             <version who=\"vpn\">{CLIENT_VERSION}</version>\
             <device-id>linux-64</device-id>\
             <auth>{fields}</auth></config-auth>"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OCSERV_USERNAME: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
<version who="sg">0.1(1)</version>
<auth id="main">
<message>Please enter your username.</message>
<form method="post" action="/auth">
<input type="text" name="username" label="Username:" />
</form></auth>
</config-auth>
"#;
    const OCSERV_PASSWORD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
<version who="sg">0.1(1)</version>
<auth id="main">
<message>Login failed.
Please enter your password.</message>
<form method="post" action="/auth">
<input type="password" name="password" label="Password:" />
</form></auth>
</config-auth>
"#;
    const OCSERV_COMPLETE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete">
<version who="sg">0.1(1)</version>
<auth id="success">
<title>SSL VPN Service</title></auth></config-auth>
"#;

    fn credentials() -> Credentials {
        Credentials {
            username: "alice".into(),
            password: "a<b&c".into(),
        }
    }
    fn form(xml: &str) -> Form {
        match parse(xml).unwrap() {
            AuthDocument::Form(form) => form,
            AuthDocument::Complete => panic!("expected a form"),
        }
    }

    #[test]
    fn ocserv_two_step_flow_escapes_values_and_completes() {
        let mut answered = Answered::default();
        let first = form(OCSERV_USERNAME);
        assert_eq!(first.action, "/auth");
        assert!(
            first
                .reply(&credentials(), &mut answered)
                .unwrap()
                .contains("<auth><username>alice</username></auth>")
        );
        assert!(
            form(OCSERV_PASSWORD)
                .reply(&credentials(), &mut answered)
                .unwrap()
                .contains("<auth><password>a&lt;b&amp;c</password></auth>")
        );
        assert_eq!(parse(OCSERV_COMPLETE).unwrap(), AuthDocument::Complete);
    }

    #[test]
    fn reprompt_after_a_submitted_password_is_a_rejection() {
        let mut answered = Answered {
            username: true,
            password: true,
        };
        assert!(matches!(
            form(OCSERV_PASSWORD).reply(&credentials(), &mut answered),
            Err(Error::Rejected)
        ));
    }

    #[test]
    fn unknown_challenge_fields_are_unsupported_and_hidden_fields_are_echoed() {
        let otp = OCSERV_PASSWORD.replace("name=\"password\"", "name=\"secondary_password\"");
        assert!(matches!(
            form(&otp).reply(&credentials(), &mut Answered::default()),
            Err(Error::Unsupported(_))
        ));
        let hidden = OCSERV_USERNAME.replace(
            "<input type=\"text\"",
            "<input type=\"hidden\" name=\"state\" value=\"x&amp;y\" /><input type=\"text\"",
        );
        assert!(
            form(&hidden)
                .reply(&credentials(), &mut Answered::default())
                .unwrap()
                .contains("<state>x&amp;y</state><username>alice</username>")
        );
    }

    #[test]
    fn malformed_documents_and_unsafe_actions_are_refused() {
        for xml in [
            "",
            "not xml",
            r#"<config-auth type="unknown"></config-auth>"#,
            r#"<config-auth type="auth-request"></config-auth>"#,
            r#"<config-auth type="auth-request"><form action="https://other.invalid/"></form></config-auth>"#,
            r#"<config-auth type="auth-request"><form action="/a b"></form></config-auth>"#,
        ] {
            assert!(parse(xml).is_err(), "{xml}");
        }
    }

    #[test]
    fn init_request_escapes_the_group_access_url() {
        assert!(init_request("https://vpn.test:443/?a&b").contains("?a&amp;b</group-access>"));
    }
}
