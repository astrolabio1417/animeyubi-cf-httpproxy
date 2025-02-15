## Deployment

This project is written in [Cloudfalre Workers](https://workers.cloudflare.com/), and can be easily deployed with [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/).
https://github.com/Zibri/cloudflare-cors-anywhere edited/forked version

```bash
npx wrangler deploy
```

## Usage Example

```javascript
fetch(
    "https://test.cors.workers.dev/?https://httpbin.org/post&x-cors-headers=",
    {
        method: "post",
        headers: {
            "x-foo": "bar",
            "x-bar": "foo",
            "x-cors-headers": JSON.stringify({
                // allows to send forbidden headers
                // https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name
                cookies: "x=123",
            }),
        },
    }
)
    .then((res) => {
        // allows to read all headers (even forbidden headers like set-cookies)
        const headers = JSON.parse(res.headers.get("cors-received-headers"));
        console.log(headers);
        return res.json();
    })
    .then(console.log);
```
