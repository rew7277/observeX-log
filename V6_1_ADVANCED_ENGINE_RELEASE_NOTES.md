# ObserveX V6.1 Advanced Engine

## Fixed

- Large uploads now use non-blocking queue mode. For files above 5 MB, the UI returns immediately after upload is accepted and analysis continues in the background.
- Upload status now clearly shows queued/running/success/failed state instead of making the user wait on the same screen.
- Curated Topology Flow now supports arrow syntax:

```text
s-gupshup-api → Request Entry → GET /verify-otp:s-gupshup-api-config.CPU-LITE → Verify OTP → Gupshup → Response Exit
```

- Selecting an API or endpoint automatically fills the Curated Topology Flow box with an editable suggested flow.
- Editing Curated Topology Flow updates the Topology graphic instantly.
- Push → Registry now saves the curated flow and applies it to existing System Map rows for the selected endpoint.
- Backend accepts arrow-separated, comma-separated, or newline-separated topology nodes.

## Notes

A 10 MB file still has to be transferred to Railway and parsed server-side, but the browser is no longer blocked waiting for full analysis. The parsed results reload automatically once the background job completes.
