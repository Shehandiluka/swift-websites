# fleet.swiftlk.com – SwiftClean Multi-PC Dashboard
Cloudflare Worker + KV. PCs send health snapshots with a team key; the web dashboard lists them and can queue "Clean now".
```
cd fleet.swiftlk.com
npx wrangler deploy          # creates the KV namespace automatically and attaches fleet.swiftlk.com
```
In SwiftClean: Options › Multi-PC Dashboard → turn on, "New key", Save. Use the same key on every PC, then open https://fleet.swiftlk.com and paste the key.
