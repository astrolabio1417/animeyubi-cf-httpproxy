/*
CORS Anywhere as a Cloudflare Worker!
(c) 2019 by Zibri (www.zibri.org)
email: zibri AT zibri DOT org
https://github.com/Zibri/cloudflare-cors-anywhere

This Cloudflare Worker script acts as a CORS proxy that allows
cross-origin resource sharing for specified origins and URLs.
It handles OPTIONS preflight requests and modifies response headers accordingly to enable CORS.
The script also includes functionality to parse custom headers and provide detailed information
about the CORS proxy service when accessed without specific parameters.
The script is configurable with whitelist and blacklist patterns, although the blacklist feature is currently unused.
The main goal is to facilitate cross-origin requests while enforcing specific security and rate-limiting policies.
*/

// Configuration: Whitelist and Blacklist (not used in this version)
// whitelist = [ "^http.?://www.zibri.org$", "zibri.org$", "test\\..*" ];  // regexp for whitelisted urls
const blacklistUrls = []; // regexp for blacklisted urls
const whitelistOrigins = [
    // ".*",
    "^https://animeyubi.com",
]; // regexp for whitelisted origins

// Function to check if a given URI or origin is listed in the whitelist or blacklist
function isListedInlist(uri, listing) {
    // When URI is null (e.g., when Origin header is missing), decide based on the implementation
    // false reject null origins, true would accept them
    if (typeof uri !== "string") return false;
    return listing.some((pattern) => uri.match(pattern) !== null);
}

// Event listener for incoming fetch requests
addEventListener("fetch", async (event) => {
    event.respondWith(
        (async function() {
            const isPreflightRequest = event.request.method === "OPTIONS";
            const originUrl = new URL(event.request.url);

            // Function to modify headers to enable CORS
            function setupCORSHeaders(headers) {
                headers.set(
                    "Access-Control-Allow-Origin",
                    event.request.headers.get("Origin")
                );

                if (!isPreflightRequest) return headers;

                headers.set(
                    "Access-Control-Allow-Methods",
                    event.request.headers.get("access-control-request-method")
                );
                const requestedHeaders = event.request.headers.get(
                    "access-control-request-headers"
                );

                if (requestedHeaders) {
                    headers.set(
                        "Access-Control-Allow-Headers",
                        requestedHeaders
                    );
                }

                headers.delete("X-Content-Type-Options"); // Remove X-Content-Type-Options header
            }

            const targetUrl = decodeURIComponent(
                decodeURIComponent(originUrl.search.substr(1))
            );

            const originHeader =
                event.request.headers.get("Origin") ||
                event.request.headers.get("Referer");
            const connectingIp = event.request.headers.get("CF-Connecting-IP");
            const isNotAllowed = !(
                !isListedInlist(targetUrl, blacklistUrls) &&
                isListedInlist(originHeader, whitelistOrigins)
            );

            if (isNotAllowed) {
                return new Response("Hello There!", {
                    status: 403,
                    statusText: "Forbidden",
                    headers: {
                        "Content-Type": "text/html",
                    },
                });
            }

            let customHeaders =
                event.request.headers.get("x-cors-headers") ||
                originUrl.searchParams.get("x-cors-headers");

            if (customHeaders !== null) {
                try {
                    customHeaders = JSON.parse(customHeaders);
                } catch (e) {}
            }

            if (!originUrl.search.startsWith("?")) {
                let responseHeaders = new Headers();
                responseHeaders = setupCORSHeaders(responseHeaders);

                let country = false;
                let colo = false;
                if (typeof event.request.cf !== "undefined") {
                    country = event.request.cf.country || false;
                    colo = event.request.cf.colo || false;
                }

                return new Response(
                    "Usage:\n" +
                        originUrl.origin +
                        "/?uri\n\n" +
                        "Limits: 100,000 requests/day\n" +
                        "          1,000 requests/10 minutes\n\n" +
                        (originHeader ? "Origin: " + originHeader + "\n" : "") +
                        "IP: " +
                        connectingIp +
                        "\n" +
                        (country ? "Country: " + country + "\n" : "") +
                        (colo ? "Datacenter: " + colo + "\n" : "") +
                        (customHeaders
                            ? "\nx-cors-headers: " +
                              JSON.stringify(customHeaders)
                            : ""),
                    {
                        status: 200,
                        headers: responseHeaders,
                    }
                );
            }

            const filteredHeaders = {};
            for (const [key, value] of event.request.headers.entries()) {
                if (
                    key.match("^origin") === null &&
                    key.match("eferer") === null &&
                    key.match("^cf-") === null &&
                    key.match("^x-forw") === null &&
                    key.match("^x-cors-headers") === null
                ) {
                    filteredHeaders[key] = value;
                }
            }

            if (customHeaders !== null) {
                Object.entries(customHeaders).forEach(
                    (entry) => (filteredHeaders[entry[0]] = entry[1])
                );
            }

            const newRequest = new Request(event.request, {
                redirect: "follow",
                headers: filteredHeaders,
            });

            const response = await fetch(targetUrl, newRequest);
            let resHeaders = new Headers(response.headers);

            const exposedHeaders = [];
            const allResponseHeaders = {};
            for (const [key, value] of response.headers.entries()) {
                exposedHeaders.push(key);
                allResponseHeaders[key] = value;
            }
            exposedHeaders.push("cors-received-headers");
            resHeaders = setupCORSHeaders(resHeaders);

            resHeaders.set(
                "Access-Control-Expose-Headers",
                exposedHeaders.join(",")
            );
            resHeaders.set(
                "cors-received-headers",
                JSON.stringify(allResponseHeaders)
            );

            const responseInit = {
                headers: resHeaders,
                status: isPreflightRequest ? 200 : response.status,
                statusText: isPreflightRequest ? "OK" : response.statusText,
            };
            return new Response(
                isPreflightRequest ? null : response.body,
                responseInit
            );
        })()
    );
});
