// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! How a CONCORD message sits in an A2A `Message` (the CONCORD A2A binding,
//! group mode).
//!
//! Every CONCORD message is one text [`Part`] carrying the verbatim CONCORD
//! XML and the media type [`MEDIA_TYPE`]. A group channel delivers each
//! message to every member, so nothing here wraps, acknowledges or addresses
//! a message: sending is [`message`], receiving is [`texts`]. This module
//! knows A2A and nothing of CONCORD itself, so it does not need the
//! `ioc-concord` library.

use a2a::{AgentSkill, Message, Part, PartContent, Role};

/// Media type of a Part that carries a CONCORD message.
pub const MEDIA_TYPE: &str = "application/vnd.ioc-project.concord+xml";

/// Id of the AgentCard skill of an agent that takes part in CONCORD runs.
pub const SKILL_ID: &str = "concord-participant";

/// The Part for one CONCORD message. `text` goes in as it is: the binding
/// forbids paraphrasing or reformatting it.
pub fn part(text: &str) -> Part {
    Part::text(text).with_media_type(MEDIA_TYPE)
}

/// The A2A message that broadcasts one CONCORD message to the group.
pub fn message(text: &str) -> Message {
    Message::new(Role::Agent, vec![part(text)])
}

/// The CONCORD messages in `message`, in order. A Part of another media type,
/// or with none, is not CONCORD and is skipped, so a group that also carries
/// other traffic does not reach the node. A `raw` Part counts when it is
/// UTF-8 text, as the binding allows it for binary-safe transport.
pub fn texts(message: &Message) -> Vec<String> {
    message
        .parts
        .iter()
        .filter(|p| is_concord(p.media_type.as_deref()))
        .filter_map(|p| match &p.content {
            PartContent::Text(t) => Some(t.clone()),
            PartContent::Raw(bytes) => String::from_utf8(bytes.clone()).ok(),
            PartContent::Url(_) | PartContent::Data(_) => None,
        })
        .collect()
}

/// Whether a media type is [`MEDIA_TYPE`], ignoring case and any parameters.
fn is_concord(media_type: Option<&str>) -> bool {
    media_type
        .and_then(|m| m.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case(MEDIA_TYPE))
}

/// The AgentCard skill that an agent implementing the participant role must
/// advertise.
pub fn participant_skill() -> AgentSkill {
    AgentSkill {
        id: SKILL_ID.to_string(),
        name: "CONCORD Participant".to_string(),
        description: "Takes part in CONCORD negotiations: receives the messages of the group \
                      and contributes to the joint decision."
            .to_string(),
        tags: vec![
            "concord".to_string(),
            "negotiation".to_string(),
            "consensus".to_string(),
        ],
        examples: None,
        input_modes: Some(vec![MEDIA_TYPE.to_string()]),
        output_modes: Some(vec![MEDIA_TYPE.to_string()]),
        security_requirements: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = "<concord-score from=\"cost\">\n  <score id=\"a\"/>\n</concord-score>";

    #[test]
    fn a_message_carries_the_text_verbatim_with_the_media_type() {
        let m = message(XML);
        assert_eq!(m.parts.len(), 1);
        assert_eq!(m.parts[0].media_type.as_deref(), Some(MEDIA_TYPE));
        assert_eq!(m.parts[0].as_text(), Some(XML));
    }

    #[test]
    fn texts_round_trips_what_message_built() {
        assert_eq!(texts(&message(XML)), vec![XML.to_string()]);
    }

    #[test]
    fn a_part_of_another_media_type_is_not_concord() {
        let m = Message::new(
            Role::Agent,
            vec![
                Part::text("hello").with_media_type("text/plain"),
                Part::text(XML),
                part(XML),
            ],
        );
        assert_eq!(texts(&m), vec![XML.to_string()]);
    }

    #[test]
    fn the_media_type_matches_ignoring_case_and_parameters() {
        let m = Message::new(
            Role::Agent,
            vec![
                Part::text("a").with_media_type("Application/Vnd.IoC-Project.Concord+XML"),
                Part::text("b").with_media_type(format!("{MEDIA_TYPE}; charset=utf-8")),
            ],
        );
        assert_eq!(texts(&m), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn a_raw_part_counts_when_it_is_utf8() {
        let m = Message::new(
            Role::Agent,
            vec![
                Part::raw(XML.as_bytes().to_vec()).with_media_type(MEDIA_TYPE),
                Part::raw(vec![0xff, 0xfe]).with_media_type(MEDIA_TYPE),
            ],
        );
        assert_eq!(texts(&m), vec![XML.to_string()]);
    }

    #[test]
    fn a_message_without_parts_has_no_texts() {
        assert!(texts(&Message::new(Role::Agent, Vec::new())).is_empty());
    }

    #[test]
    fn the_skill_declares_the_binding_modes() {
        let skill = participant_skill();
        assert_eq!(skill.id, SKILL_ID);
        assert_eq!(skill.input_modes, Some(vec![MEDIA_TYPE.to_string()]));
        assert_eq!(skill.output_modes, Some(vec![MEDIA_TYPE.to_string()]));
    }
}
