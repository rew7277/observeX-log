# V32 Dynamic Masking Settings

Added Settings-driven masking governance:

- New `MaskingRule` table per user.
- New `/settings/masking` GET/POST API.
- New `/settings/masking/reprocess` endpoint for re-masking stored rows.
- Default configurable fields: Phone, Email, BankAc, Amt, CollectionAmt, AppID, MerchantKey, Ref1, Ref2, Cust1/Cust2/Cust3, IFSC, MICR.
- Mask types: `full`, `partial`, `hash`, `searchable_mask`.
- `Ref1: APPT625409` now renders as `[MASKED_ID:625409]`, so searching `625409` works while the full value remains masked.
- Existing fully masked historical rows cannot recover original values; re-upload original logs after changing masking rules.
