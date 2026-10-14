use super::*;

#[test]
fn collecting_sink_keeps_events_in_order() {
    let sink = CollectingSink::new();
    sink.emit("b1", SandboxEvent::Started);
    sink.emit(
        "b1",
        SandboxEvent::LimitHit {
            limit: LimitKind::Memory,
        },
    );
    sink.emit("b1", SandboxEvent::Exited { status: Some(137) });
    let events = sink.events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].1, SandboxEvent::Started);
    assert_eq!(
        events[1].1,
        SandboxEvent::LimitHit {
            limit: LimitKind::Memory
        }
    );
    assert_eq!(events[2].1, SandboxEvent::Exited { status: Some(137) });
}

#[test]
fn denied_event_round_trips_through_json() {
    let event = SandboxEvent::Denied {
        kind: DenialKind::Network,
        target: Some("169.254.169.254:80".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert_eq!(serde_json::from_str::<SandboxEvent>(&json).unwrap(), event);
}
