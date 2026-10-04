use hickory_proto::op::{Message, ResponseCode};

pub const MAX_DNS_MESSAGE: usize = u16::MAX as usize;
/// A DNS header is fixed-size: ID, flags, and the four count fields
/// (question/answer/authority/additional), 2 bytes each — 12 total.
pub const MIN_DNS_MESSAGE: usize = 12;

#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Complete(Vec<u8>),
    Invalid,
    Incomplete,
}

pub fn take_frame(buf: &mut Vec<u8>) -> Frame {
    if buf.len() < 2 {
        return Frame::Incomplete;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if len < MIN_DNS_MESSAGE {
        return Frame::Invalid;
    }
    if buf.len() < 2 + len {
        return Frame::Incomplete;
    }
    let msg = buf[2..2 + len].to_vec();
    buf.drain(..2 + len);
    Frame::Complete(msg)
}

pub fn encode_frame(msg: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(2 + msg.len());
    frame.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    frame.extend_from_slice(msg);
    frame
}

pub fn parse(bytes: &[u8]) -> Option<Message> {
    Message::from_vec(bytes).ok()
}

pub fn describe_query(query: &[u8]) -> String {
    match parse(query) {
        Some(msg) => match msg.queries.first() {
            Some(q) => format!("{} {}", q.name(), q.query_type()),
            None => "<no question>".to_string(),
        },
        None => "<malformed query>".to_string(),
    }
}

pub fn rcode_name(resp: &[u8]) -> String {
    parse(resp)
        .map(|msg| msg.metadata.response_code.to_string())
        .unwrap_or_else(|| "<malformed>".to_string())
}

pub fn is_truncated(resp: &[u8]) -> bool {
    parse(resp).is_some_and(|msg| msg.metadata.truncation)
}

pub fn query_id(msg: &[u8]) -> Option<u16> {
    parse(msg).map(|msg| msg.metadata.id)
}

pub fn response_for(query: &Message, code: ResponseCode) -> Message {
    let mut resp = Message::error_msg(query.metadata.id, query.metadata.op_code, code);
    for q in &query.queries {
        resp.add_query(q.clone());
    }
    resp
}

pub fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    response_for(&parse(query)?, ResponseCode::ServFail)
        .to_vec()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    #[test]
    fn frame_roundtrip() {
        let msg = vec![0xAB; 40];
        let framed = encode_frame(&msg);
        assert_eq!(framed.len(), 42);

        let mut buf = framed[..3].to_vec();
        assert_eq!(take_frame(&mut buf), Frame::Incomplete);

        let mut buf = framed.clone();
        match take_frame(&mut buf) {
            Frame::Complete(m) => assert_eq!(m, msg),
            other => panic!("expected complete frame, got {other:?}"),
        }
        assert!(buf.is_empty());

        let mut buf = [framed.as_slice(), framed.as_slice()].concat();
        assert_eq!(take_frame(&mut buf), Frame::Complete(msg.clone()));
        assert_eq!(take_frame(&mut buf), Frame::Complete(msg));
        assert!(buf.is_empty());
    }

    #[test]
    fn frame_invalid_on_short_declared_length() {
        let mut buf = vec![0u8, 5, 9, 9, 9, 9, 9];
        assert_eq!(take_frame(&mut buf), Frame::Invalid);
    }

    #[test]
    fn truncated_flag_detection() {
        let mut resp = Message::new(0, MessageType::Response, OpCode::Query);
        assert!(!is_truncated(&resp.to_vec().unwrap()));

        resp.metadata.truncation = true;
        assert!(is_truncated(&resp.to_vec().unwrap()));

        // Unparseable responses count as complete, never truncated.
        assert!(!is_truncated(&[0u8; 3]));
    }

    #[test]
    fn rcode_of_unparseable_response() {
        assert_eq!(rcode_name(&[0u8; 3]), "<malformed>");
    }

    #[test]
    fn response_for_echoes_query() {
        let name = Name::from_ascii("example.com.").unwrap();
        let mut query = Message::new(0x1234, MessageType::Query, OpCode::Status);
        query.add_query(Query::query(name, RecordType::A));
        let resp = response_for(&query, ResponseCode::Refused);
        assert_eq!(resp.metadata.id, 0x1234);
        assert_eq!(resp.metadata.op_code, OpCode::Status);
        assert_eq!(resp.queries.len(), 1);
    }
}
