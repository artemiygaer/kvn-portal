/* Фрагмент для playwright-cli run-code --filename: один обзор, холодный HTTP-кэш. */
async (page) => {
    const url = new URL(page.url());
    if (url.hostname !== "127.0.0.1" || !["8443", "18443"].includes(url.port))
        throw new Error("Замер разрешён только через loopback-стенды");
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("Network.enable");
    await cdp.send("Network.setCacheDisabled", {cacheDisabled: true});
    const results = [];
    for (let trial = 0; trial < 3; trial += 1) {
        const requests = [];
        const collect = (request) => requests.push([request.resourceType(), new URL(request.url()).pathname]);
        page.on("request", collect);
        try {
            const response = await page.goto(url.href, {waitUntil: "load"});
            if (!response || response.status() !== 200 || page.url() !== url.href)
                throw new Error("Обзор не ответил HTTP 200 по ожидаемому URL");
            await page.waitForTimeout(1800);
            results.push(await page.evaluate(() => {
                const nav = performance.getEntriesByType("navigation")[0];
                const assets = performance.getEntriesByType("resource");
                const payload = assets.filter((row) => /\.(?:css|js)(?:\?|$)/.test(row.name));
                return {
                    html_css_js_body_bytes: nav.encodedBodySize + payload.reduce((sum, row) => sum + row.encodedBodySize, 0),
                    load_ms: Math.round(nav.loadEventEnd),
                    ttfb_ms: Math.round(nav.responseStart),
                    js: payload.filter((row) => /\.js(?:\?|$)/.test(row.name)).length,
                    external: assets.filter((row) => new URL(row.name).origin !== location.origin).length,
                };
            }));
            results.at(-1).requests = requests;
        } finally {
            page.off("request", collect);
        }
    }
    return results;
}
