
#[cfg(test)]
pub mod tests {
    use hopr_bindings::{exports::alloy::sol_types::SolCall, hopr_channels::HoprChannels::redeemTicketCall};
    use hopr_types::internal::tickets::REDEEM_CALL_SELECTOR;

    #[test]
    fn test_redeem_ticket_selector_match_with_binding() {
        assert_eq!(REDEEM_CALL_SELECTOR, redeemTicketCall::SELECTOR);
    }
}
