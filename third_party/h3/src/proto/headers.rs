use std::{
    convert::TryFrom,
    fmt,
    iter::{IntoIterator, Iterator},
    str::FromStr,
};

use http::{
    header::{self, HeaderName, HeaderValue},
    uri::{self, Authority, Parts, PathAndQuery, Scheme, Uri},
    Extensions, HeaderMap, Method, StatusCode,
};

use crate::{ext::Protocol, qpack::HeaderField};

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Clone))]
pub struct Header {
    pseudo: Pseudo,
    fields: HeaderMap,
}

#[allow(clippy::len_without_is_empty)]
impl Header {
    /// Creates a new `Header` frame data suitable for sending a request
    pub fn request(
        method: Method,
        uri: Uri,
        fields: HeaderMap,
        ext: Extensions,
    ) -> Result<Self, HeaderError> {
        match (uri.authority(), fields.get("host")) {
            (None, None) => Err(HeaderError::MissingAuthority),
            (Some(a), Some(h)) if a.as_str() != h => Err(HeaderError::ContradictedAuthority),
            _ => Ok(Self {
                pseudo: Pseudo::request(method, uri, ext),
                fields,
            }),
        }
    }

    pub fn response(status: StatusCode, fields: HeaderMap) -> Self {
        Self {
            pseudo: Pseudo::response(status),
            fields,
        }
    }

    pub fn trailer(fields: HeaderMap) -> Self {
        Self {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
            //# Pseudo-header fields MUST NOT appear in trailer
            //# sections.
            pseudo: Pseudo::default(),
            fields,
        }
    }

    pub fn into_request_parts(
        self,
    ) -> Result<(Method, Uri, Option<Protocol>, HeaderMap), HeaderError> {
        let mut uri = Uri::builder();

        if let Some(path) = self.pseudo.path {
            uri = uri.path_and_query(path.as_str().as_bytes());
        }

        if let Some(scheme) = self.pseudo.scheme {
            uri = uri.scheme(scheme.as_str().as_bytes());
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=TODO
        //# If the scheme does not have a mandatory authority component and none
        //# is provided in the request target, the request MUST NOT contain the
        //# :authority pseudo-header or Host header fields.
        match (self.pseudo.authority, self.fields.get("host")) {
            (None, None) => return Err(HeaderError::MissingAuthority),
            (Some(a), None) => uri = uri.authority(a.as_str().as_bytes()),
            (None, Some(h)) => uri = uri.authority(h.as_bytes()),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If both fields are present, they MUST contain the same value.
            (Some(a), Some(h)) if a.as_str() != h => {
                return Err(HeaderError::ContradictedAuthority)
            }
            (Some(_), Some(h)) => uri = uri.authority(h.as_bytes()),
        }

        Ok((
            self.pseudo.method.ok_or(HeaderError::MissingMethod)?,
            // When empty host field is built into an uri it fails
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If these fields are present, they MUST NOT be
            //# empty.
            uri.build().map_err(HeaderError::InvalidRequest)?,
            self.pseudo.protocol,
            self.fields,
        ))
    }

    pub fn into_response_parts(self) -> Result<(StatusCode, HeaderMap), HeaderError> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.2
        //= type=implication
        //# For responses, a single ":status" pseudo-header field is defined that
        //# carries the HTTP status code; see Section 15 of [HTTP].  This pseudo-
        //# header field MUST be included in all responses; otherwise, the
        //# response is malformed (see Section 4.1.2).
        Ok((
            self.pseudo.status.ok_or(HeaderError::MissingStatus)?,
            self.fields,
        ))
    }

    pub fn into_fields(self) -> HeaderMap {
        self.fields
    }

    pub fn len(&self) -> usize {
        self.pseudo.len() + self.fields.len()
    }

    pub fn size(&self) -> usize {
        self.pseudo.len() + self.fields.len()
    }

    #[cfg(test)]
    pub(crate) fn authory_mut(&mut self) -> &mut Option<Authority> {
        &mut self.pseudo.authority
    }
}

impl IntoIterator for Header {
    type Item = HeaderField;
    type IntoIter = HeaderIter;
    fn into_iter(self) -> Self::IntoIter {
        HeaderIter {
            pseudo: Some(self.pseudo),
            last_header_name: None,
            fields: self.fields.into_iter(),
        }
    }
}

pub struct HeaderIter {
    pseudo: Option<Pseudo>,
    last_header_name: Option<HeaderName>,
    fields: header::IntoIter<HeaderValue>,
}

impl Iterator for HeaderIter {
    type Item = HeaderField;

    fn next(&mut self) -> Option<Self::Item> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //# All pseudo-header fields MUST appear in the header section before
        //# regular header fields.
        if let Some(ref mut pseudo) = self.pseudo {
            if let Some(method) = pseudo.method.take() {
                return Some((":method", method.as_str()).into());
            }

            if let Some(scheme) = pseudo.scheme.take() {
                return Some((":scheme", scheme.as_str().as_bytes()).into());
            }

            if let Some(authority) = pseudo.authority.take() {
                return Some((":authority", authority.as_str().as_bytes()).into());
            }

            if let Some(path) = pseudo.path.take() {
                return Some((":path", path.as_str().as_bytes()).into());
            }

            if let Some(status) = pseudo.status.take() {
                return Some((":status", status.as_str()).into());
            }

            if let Some(protocol) = pseudo.protocol.take() {
                return Some((":protocol", protocol.as_str().as_bytes()).into());
            }
        }

        self.pseudo = None;

        for (new_header_name, header_value) in self.fields.by_ref() {
            if let Some(new) = new_header_name {
                self.last_header_name = Some(new);
            }
            if let (Some(ref n), v) = (&self.last_header_name, header_value) {
                return Some((n.as_str(), v.as_bytes()).into());
            }
        }

        None
    }
}

impl TryFrom<Vec<HeaderField>> for Header {
    type Error = HeaderError;
    fn try_from(headers: Vec<HeaderField>) -> Result<Self, Self::Error> {
        let mut fields = HeaderMap::with_capacity(headers.len());
        let mut pseudo = Pseudo::default();
        let mut ordinary_seen = false;
        let mut pseudo_seen = 0u8;

        for field in headers.into_iter() {
            let (name, value) = field.into_inner();
            // 在原始字段顺序仍可见时拒绝覆盖，不能留到Request/Response还原之后。
            if name.starts_with(b":") {
                let bit = match name.as_ref() {
                    b":method" => 1,
                    b":scheme" => 2,
                    b":authority" => 4,
                    b":path" => 8,
                    b":status" => 16,
                    b":protocol" => 32,
                    _ => 0,
                };
                if ordinary_seen || (pseudo_seen & bit) != 0 {
                    return Err(HeaderError::InvalidHeaderName(
                        "伪头字段重复或位于普通字段之后".into(),
                    ));
                }
                pseudo_seen |= bit;
            } else {
                ordinary_seen = true;
            }
            match Field::parse(name, value)? {
                Field::Method(m) => {
                    pseudo.method = Some(m);
                    pseudo.len += 1;
                }
                Field::Scheme(s) => {
                    pseudo.scheme = Some(s);
                    pseudo.len += 1;
                }
                Field::Authority(a) => {
                    pseudo.authority = Some(a);
                    pseudo.len += 1;
                }
                Field::Path(p) => {
                    pseudo.path = Some(p);
                    pseudo.len += 1;
                }
                Field::Status(s) => {
                    pseudo.status = Some(s);
                    pseudo.len += 1;
                }
                Field::Header((n, v)) => {
                    fields.append(n, v);
                }
                Field::Protocol(p) => {
                    pseudo.protocol = Some(p);
                    pseudo.len += 1;
                }
            }
        }

        Ok(Header { pseudo, fields })
    }
}

enum Field {
    Method(Method),
    Scheme(Scheme),
    Authority(Authority),
    Path(PathAndQuery),
    Status(StatusCode),
    Protocol(Protocol),
    Header((HeaderName, HeaderValue)),
}

impl Field {
    fn parse<N, V>(name: N, value: V) -> Result<Self, HeaderError>
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let name = name.as_ref();
        if name.is_empty() {
            return Err(HeaderError::InvalidHeaderName("name is empty".into()));
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
        //# Requests or responses containing invalid field names MUST be treated
        //# as malformed.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
        //# Any request or response that contains a
        //# character not permitted in a field value MUST be treated as
        //# malformed.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //= type=implication
        //# A request or
        //# response containing uppercase characters in field names MUST be
        //# treated as malformed.

        if name[0] != b':' {
            return Ok(Field::Header((
                HeaderName::from_lowercase(name).map_err(|_| HeaderError::invalid_name(name))?,
                HeaderValue::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            )));
        }

        Ok(match name {
            b":scheme" => Field::Scheme(try_value(name, value)?),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If these fields are present, they MUST NOT be
            //# empty.
            b":authority" => Field::Authority(try_value(name, value)?),
            b":path" => Field::Path(try_value(name, value)?),
            b":method" => Field::Method(
                Method::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            ),
            b":status" => Field::Status(
                StatusCode::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            ),
            b":protocol" => Field::Protocol(try_value(name, value)?),
            _ => return Err(HeaderError::invalid_name(name)),
        })
    }
}

fn try_value<N, V, R>(name: N, value: V) -> Result<R, HeaderError>
where
    N: AsRef<[u8]>,
    V: AsRef<[u8]>,
    R: FromStr,
{
    let (name, value) = (name.as_ref(), value.as_ref());
    let s = std::str::from_utf8(value).map_err(|_| HeaderError::invalid_value(name, value))?;
    R::from_str(s).map_err(|_| HeaderError::invalid_value(name, value))
}

/// Pseudo-header fields have the same purpose as data from the first line of HTTP/1.X,
/// but are conveyed along with other headers. For example ':method' and ':path' in a
/// request, and ':status' in a response. They must be placed before all other fields,
/// start with ':', and be lowercase.
/// See RFC7540 section 8.1.2.1. for more details.
#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq, Clone))]
struct Pseudo {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //= type=implication
    //# Endpoints MUST NOT
    //# generate pseudo-header fields other than those defined in this
    //# document.

    // Request
    method: Option<Method>,
    scheme: Option<Scheme>,
    authority: Option<Authority>,
    path: Option<PathAndQuery>,

    // Response
    status: Option<StatusCode>,

    protocol: Option<Protocol>,

    len: usize,
}

#[allow(clippy::len_without_is_empty)]
impl Pseudo {
    fn request(method: Method, uri: Uri, ext: Extensions) -> Self {
        let Parts {
            scheme,
            authority,
            path_and_query,
            ..
        } = uri::Parts::from(uri);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=implication
        //# This pseudo-header field MUST NOT be empty for "http" or "https"
        //# URIs; "http" or "https" URIs that do not contain a path component
        //# MUST include a value of / (ASCII 0x2f).
        let path = path_and_query.map_or_else(
            || PathAndQuery::from_static("/"),
            |path| {
                if path.path().is_empty() && method != Method::OPTIONS {
                    PathAndQuery::from_static("/")
                } else {
                    path
                }
            },
        );

        // If the method is connect, the `:protocol` pseudo-header MAY be defined
        //
        // See: [https://www.rfc-editor.org/rfc/rfc8441#section-4]
        let protocol = if method == Method::CONNECT {
            ext.get::<Protocol>().copied()
        } else {
            None
        };

        // 回移官方#322：没有:protocol的classic CONNECT只发送方法与authority。
        let (scheme, path) = if method == Method::CONNECT && protocol.is_none() {
            (None, None)
        } else {
            (scheme.or(Some(Scheme::HTTPS)), Some(path))
        };

        // 按实际存在的字段计数；普通请求和extended CONNECT的计数保持原值。
        let len = 1
            + scheme.is_some() as usize
            + authority.is_some() as usize
            + path.is_some() as usize
            + protocol.is_some() as usize;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=implication
        //# Pseudo-header fields defined for requests MUST NOT appear
        //# in responses; pseudo-header fields defined for responses MUST NOT
        //# appear in requests.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=implication
        //# All HTTP/3 requests MUST include exactly one value for the :method,
        //# :scheme, and :path pseudo-header fields, unless the request is a
        //# CONNECT request; see Section 4.4.
        Self {
            method: Some(method),
            scheme,
            authority,
            path,
            status: None,
            protocol,
            len,
        }
    }

    fn response(status: StatusCode) -> Self {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=implication
        //# Pseudo-header fields defined for requests MUST NOT appear
        //# in responses; pseudo-header fields defined for responses MUST NOT
        //# appear in requests.
        Pseudo {
            method: None,
            scheme: None,
            authority: None,
            path: None,
            status: Some(status),
            len: 1,
            protocol: None,
        }
    }

    fn len(&self) -> usize {
        self.len
    }
}

#[derive(Debug)]
pub enum HeaderError {
    InvalidHeaderName(String),
    InvalidHeaderValue(String),
    InvalidRequest(http::Error),
    MissingMethod,
    MissingStatus,
    MissingAuthority,
    ContradictedAuthority,
}

impl HeaderError {
    fn invalid_name<N>(name: N) -> Self
    where
        N: AsRef<[u8]>,
    {
        HeaderError::InvalidHeaderName(format!("{:?}", name.as_ref()))
    }

    fn invalid_value<N, V>(name: N, value: V) -> Self
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        HeaderError::InvalidHeaderValue(format!(
            "{:?} {:?}",
            String::from_utf8_lossy(name.as_ref()),
            value.as_ref()
        ))
    }
}

impl std::error::Error for HeaderError {}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::InvalidHeaderName(h) => write!(f, "invalid header name: {}", h),
            HeaderError::InvalidHeaderValue(v) => write!(f, "invalid header value: {}", v),
            HeaderError::InvalidRequest(r) => write!(f, "invalid request: {}", r),
            HeaderError::MissingMethod => write!(f, "missing method in request headers"),
            HeaderError::MissingStatus => write!(f, "missing status in response headers"),
            HeaderError::MissingAuthority => write!(f, "missing authority"),
            HeaderError::ContradictedAuthority => {
                write!(f, "uri and authority field are in contradiction")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    fn qpack_fields(fields: Vec<HeaderField>) -> Vec<HeaderField> {
        let mut wire = bytes::BytesMut::new();
        crate::qpack::encode_stateless(&mut wire, fields).unwrap();
        crate::qpack::decode_stateless(&mut wire.as_ref(), u64::MAX)
            .unwrap()
            .fields
    }

    #[test]
    fn duplicate_pseudo_fields_never_overwrite_identical_or_distinct_values() {
        for (name, first, second) in [
            (":method", "CONNECT", "GET"),
            (":scheme", "https", "http"),
            (":authority", "example.invalid:443", "other.invalid:8443"),
            (":path", "/first", "/second"),
            (":status", "200", "403"),
            (":protocol", "webtransport", "connect-udp"),
        ] {
            assert!(Header::try_from(vec![(name, first).into()]).is_ok());
            for repeated in [first, second] {
                let fields = qpack_fields(vec![(name, first).into(), (name, repeated).into()]);
                assert_matches!(
                    Header::try_from(fields),
                    Err(HeaderError::InvalidHeaderName(_))
                );
            }
        }
    }

    #[test]
    fn classic_connect_rejects_duplicate_method_and_authority_after_qpack() {
        for duplicate in [
            (":method", "CONNECT"),
            (":method", "GET"),
            (":authority", "example.invalid:443"),
            (":authority", "other.invalid:8443"),
        ] {
            let fields = qpack_fields(vec![
                (":method", "CONNECT").into(),
                (":authority", "example.invalid:443").into(),
                duplicate.into(),
            ]);
            assert_matches!(
                Header::try_from(fields),
                Err(HeaderError::InvalidHeaderName(_))
            );
        }
    }

    #[test]
    fn response_rejects_duplicate_status_after_qpack() {
        for repeated in ["200", "407"] {
            let fields = qpack_fields(vec![
                (":status", "200").into(),
                (":status", repeated).into(),
            ]);
            assert_matches!(
                Header::try_from(fields),
                Err(HeaderError::InvalidHeaderName(_))
            );
        }
    }

    #[test]
    fn every_pseudo_field_must_precede_all_ordinary_fields() {
        for pseudo in [
            (":method", "CONNECT"),
            (":scheme", "https"),
            (":authority", "example.invalid:443"),
            (":path", "/"),
            (":status", "200"),
            (":protocol", "webtransport"),
        ] {
            let fields = qpack_fields(vec![("x-test", "ordinary").into(), pseudo.into()]);
            assert_matches!(
                Header::try_from(fields),
                Err(HeaderError::InvalidHeaderName(_))
            );
        }
    }

    #[test]
    fn arbitrary_valid_pseudo_order_keeps_repeated_ordinary_fields() {
        let pseudo: Vec<HeaderField> = vec![
            (":method", "GET").into(),
            (":scheme", "https").into(),
            (":authority", "example.invalid:443").into(),
            (":path", "/resource").into(),
        ];
        for rotation in 0..pseudo.len() {
            let mut fields = pseudo.clone();
            fields.rotate_left(rotation);
            fields.extend([("x-test", "first").into(), ("x-test", "second").into()]);
            let rebuilt = Header::try_from(qpack_fields(fields)).unwrap();
            let (method, uri, _, fields) = rebuilt.into_request_parts().unwrap();
            assert_eq!(method, Method::GET);
            assert_eq!(uri.to_string(), "https://example.invalid:443/resource");
            let values: Vec<_> = fields
                .get_all("x-test")
                .iter()
                .map(|v| v.as_bytes())
                .collect();
            assert_eq!(values, [b"first".as_slice(), b"second".as_slice()]);
        }
    }

    // 用独立列出的标准字段比较请求构造、迭代、QPACK和接收还原，避免只检查内部Option。
    fn assert_fields_and_qpack(header: Header, expected: Vec<HeaderField>) -> Header {
        assert_eq!(header.len(), expected.len());
        assert_eq!(header.size(), expected.len());
        assert_eq!(header.clone().into_iter().collect::<Vec<_>>(), expected);
        let expected_size = expected.iter().map(HeaderField::mem_size).sum::<usize>() as u64;
        let mut wire = bytes::BytesMut::new();
        let encoded_size = crate::qpack::encode_stateless(&mut wire, header).unwrap();
        let mut canonical = bytes::BytesMut::new();
        let canonical_size =
            crate::qpack::encode_stateless(&mut canonical, expected.clone()).unwrap();
        assert_eq!(wire, canonical);
        assert_eq!(encoded_size, canonical_size);
        assert_eq!(encoded_size, expected_size);
        let mut input = wire.as_ref();
        let decoded = crate::qpack::decode_stateless(&mut input, expected_size).unwrap();
        assert!(input.is_empty());
        assert_eq!(decoded.fields, expected);
        assert_eq!(decoded.mem_size, expected_size);
        let mut limited = wire.as_ref();
        assert_matches!(
            crate::qpack::decode_stateless(&mut limited, expected_size - 1),
            Err(crate::qpack::DecoderError::HeaderTooLong(size)) if size == expected_size
        );
        let rebuilt = Header::try_from(decoded.fields).unwrap();
        assert_eq!(rebuilt.len(), expected.len());
        assert_eq!(rebuilt.clone().into_iter().collect::<Vec<_>>(), expected);
        rebuilt
    }

    fn classic(authority: &str) -> Header {
        Header::request(
            Method::CONNECT,
            Uri::builder().authority(authority).build().unwrap(),
            HeaderMap::new(),
            Extensions::new(),
        )
        .unwrap()
    }

    #[test]
    fn classic_connect_omits_scheme_path_and_reports_exact_count() {
        for authority in ["example.invalid:443", "127.0.0.1:8443", "[::1]:443"] {
            let header = classic(authority);
            assert_eq!(header.pseudo.len(), 2);
            assert!(header.pseudo.scheme.is_none());
            assert!(header.pseudo.path.is_none());
            assert!(header.pseudo.protocol.is_none());
            assert_fields_and_qpack(
                header,
                vec![
                    (":method", "CONNECT").into(),
                    (":authority", authority).into(),
                ],
            );
        }
    }

    #[test]
    fn classic_connect_absolute_uri_also_omits_scheme_path() {
        let header = Header::request(
            Method::CONNECT,
            "https://example.invalid:443/ignored?query=ignored"
                .parse()
                .unwrap(),
            HeaderMap::new(),
            Extensions::new(),
        )
        .unwrap();
        assert_fields_and_qpack(
            header,
            vec![
                (":method", "CONNECT").into(),
                (":authority", "example.invalid:443").into(),
            ],
        );
    }

    #[test]
    fn classic_connect_qpack_serialization_and_limits() {
        let mut fields = HeaderMap::new();
        fields.append("x-test", "first".parse().unwrap());
        fields.append("x-test", "second".parse().unwrap());
        let header = Header::request(
            Method::CONNECT,
            Uri::builder()
                .authority("example.invalid:443")
                .build()
                .unwrap(),
            fields,
            Extensions::new(),
        )
        .unwrap();
        assert_fields_and_qpack(
            header,
            vec![
                (":method", "CONNECT").into(),
                (":authority", "example.invalid:443").into(),
                ("x-test", "first").into(),
                ("x-test", "second").into(),
            ],
        );
    }

    #[test]
    fn classic_connect_authority_only_decode_accepts_tunnel_tokens() {
        for authority in [
            "_udp2",
            "_check",
            "_icmp",
            "example.invalid:443",
            "[::1]:8443",
        ] {
            let rebuilt = assert_fields_and_qpack(
                classic(authority),
                vec![
                    (":method", "CONNECT").into(),
                    (":authority", authority).into(),
                ],
            );
            let (method, uri, protocol, fields) = rebuilt.into_request_parts().unwrap();
            assert_eq!(method, Method::CONNECT);
            assert_eq!(uri.authority().unwrap().as_str(), authority);
            assert!(uri.scheme().is_none());
            assert!(uri.path_and_query().is_none());
            assert!(protocol.is_none());
            assert!(fields.is_empty());
        }
    }

    #[test]
    fn ordinary_get_post_pseudo_fields_and_qpack_unchanged() {
        for method in [Method::GET, Method::POST] {
            for (uri, scheme, authority, path) in [
                ("https://example.invalid", "https", "example.invalid", "/"),
                (
                    "https://example.invalid/resource?query=value",
                    "https",
                    "example.invalid",
                    "/resource?query=value",
                ),
                (
                    "http://127.0.0.1:8080/upload",
                    "http",
                    "127.0.0.1:8080",
                    "/upload",
                ),
            ] {
                let mut fields = HeaderMap::new();
                fields.insert("x-test", "value".parse().unwrap());
                let header = Header::request(
                    method.clone(),
                    uri.parse().unwrap(),
                    fields,
                    Extensions::new(),
                )
                .unwrap();
                assert_eq!(header.pseudo.len(), 4);
                let rebuilt = assert_fields_and_qpack(
                    header,
                    vec![
                        (":method", method.as_str()).into(),
                        (":scheme", scheme).into(),
                        (":authority", authority).into(),
                        (":path", path).into(),
                        ("x-test", "value").into(),
                    ],
                );
                let (received_method, uri, protocol, _) = rebuilt.into_request_parts().unwrap();
                assert_eq!(received_method, method);
                assert_eq!(uri.scheme_str(), Some(scheme));
                assert_eq!(uri.authority().unwrap().as_str(), authority);
                assert_eq!(uri.path_and_query().unwrap().as_str(), path);
                assert!(protocol.is_none());
            }
        }
    }

    #[test]
    fn ordinary_authority_and_origin_forms_keep_defaults() {
        for method in [Method::GET, Method::POST] {
            let header = Header::request(
                method.clone(),
                Uri::builder()
                    .authority("example.invalid:443")
                    .build()
                    .unwrap(),
                HeaderMap::new(),
                Extensions::new(),
            )
            .unwrap();
            assert_fields_and_qpack(
                header,
                vec![
                    (":method", method.as_str()).into(),
                    (":scheme", "https").into(),
                    (":authority", "example.invalid:443").into(),
                    (":path", "/").into(),
                ],
            );
            let mut fields = HeaderMap::new();
            fields.insert("host", "example.invalid:443".parse().unwrap());
            let header = Header::request(
                method.clone(),
                "/origin?query=value".parse().unwrap(),
                fields,
                Extensions::new(),
            )
            .unwrap();
            assert_fields_and_qpack(
                header,
                vec![
                    (":method", method.as_str()).into(),
                    (":scheme", "https").into(),
                    (":path", "/origin?query=value").into(),
                    ("host", "example.invalid:443").into(),
                ],
            );
        }
    }

    #[test]
    fn extended_connect_protocols_preserve_pseudo_fields_and_qpack() {
        for protocol in [Protocol::WEB_TRANSPORT, Protocol::CONNECT_UDP] {
            for (uri, path) in [
                (
                    "https://example.invalid/tunnel?query=value"
                        .parse()
                        .unwrap(),
                    "/tunnel?query=value",
                ),
                (
                    Uri::builder().authority("example.invalid").build().unwrap(),
                    "/",
                ),
            ] {
                let mut ext = Extensions::new();
                ext.insert(protocol);
                let header = Header::request(Method::CONNECT, uri, HeaderMap::new(), ext).unwrap();
                assert_eq!(header.pseudo.len(), 5);
                let rebuilt = assert_fields_and_qpack(
                    header,
                    vec![
                        (":method", "CONNECT").into(),
                        (":scheme", "https").into(),
                        (":authority", "example.invalid").into(),
                        (":path", path).into(),
                        (":protocol", protocol.as_str()).into(),
                    ],
                );
                let (method, uri, received_protocol, _) = rebuilt.into_request_parts().unwrap();
                assert_eq!(method, Method::CONNECT);
                assert_eq!(received_protocol, Some(protocol));
                assert_eq!(uri.scheme_str(), Some("https"));
                assert_eq!(uri.path_and_query().unwrap().as_str(), path);
            }
        }
    }

    #[test]
    fn non_connect_protocol_extension_remains_ignored() {
        for method in [Method::GET, Method::POST] {
            let mut ext = Extensions::new();
            ext.insert(Protocol::WEB_TRANSPORT);
            let header = Header::request(
                method.clone(),
                "https://example.invalid/".parse().unwrap(),
                HeaderMap::new(),
                ext,
            )
            .unwrap();
            assert_eq!(header.pseudo.len(), 4);
            assert_fields_and_qpack(
                header,
                vec![
                    (":method", method.as_str()).into(),
                    (":scheme", "https").into(),
                    (":authority", "example.invalid").into(),
                    (":path", "/").into(),
                ],
            );
        }
    }

    #[test]
    fn request_has_no_authority_nor_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![(b":method", Method::GET.as_str()).into()]).unwrap();
        assert!(headers.pseudo.authority.is_none());
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::MissingAuthority)
        );
    }

    #[test]
    fn request_has_empty_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If these fields are present, they MUST NOT be
        //# empty.
        assert_matches!(
            Header::try_from(vec![
                (b":method", Method::GET.as_str()).into(),
                (b":authority", b"").into(),
            ]),
            Err(HeaderError::InvalidHeaderValue(_))
        );
    }

    #[test]
    fn request_has_empty_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If these fields are present, they MUST NOT be
        //# empty.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b"host", b"").into(),
        ])
        .unwrap();
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::InvalidRequest(_))
        );
    }

    #[test]
    fn request_has_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
        ])
        .unwrap();
        assert_matches!(headers.into_request_parts(), Ok(_));
    }

    #[test]
    fn request_has_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b"host", b"test.com").into(),
        ])
        .unwrap();
        assert!(headers.pseudo.authority.is_none());
        assert_matches!(headers.into_request_parts(), Ok(_));
    }

    #[test]
    fn request_has_same_host_and_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If both fields are present, they MUST contain the same value.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
            (b"host", b"test.com").into(),
        ])
        .unwrap();
        assert_matches!(headers.into_request_parts(), Ok(_));
    }
    #[test]
    fn request_has_different_host_and_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If both fields are present, they MUST contain the same value.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"authority.com").into(),
            (b"host", b"host.com").into(),
        ])
        .unwrap();
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::ContradictedAuthority)
        );
    }

    #[test]
    fn preserves_duplicate_headers() {
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
            (b"set-cookie", b"foo=foo").into(),
            (b"set-cookie", b"bar=bar").into(),
            (b"other-header", b"other-header-value").into(),
        ])
        .unwrap();

        assert_eq!(
            headers
                .clone()
                .into_iter()
                .filter(|h| h.name.as_ref() == b"set-cookie")
                .collect::<Vec<_>>(),
            vec![
                HeaderField {
                    name: std::borrow::Cow::Borrowed(b"set-cookie"),
                    value: std::borrow::Cow::Borrowed(b"foo=foo")
                },
                HeaderField {
                    name: std::borrow::Cow::Borrowed(b"set-cookie"),
                    value: std::borrow::Cow::Borrowed(b"bar=bar")
                }
            ]
        );
        assert_eq!(
            headers
                .into_iter()
                .filter(|h| h.name.as_ref() == b"other-header")
                .collect::<Vec<_>>(),
            vec![HeaderField {
                name: std::borrow::Cow::Borrowed(b"other-header"),
                value: std::borrow::Cow::Borrowed(b"other-header-value")
            },]
        );
    }
}
