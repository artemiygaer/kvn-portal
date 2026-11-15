/* Фрагмент для playwright-cli. Проверки только существующих страниц v5. */
async (page) => {
    const origin = "https://127.0.0.1:8443";
    if (new URL(page.url()).origin !== origin) throw new Error("Ожидается локальная панель");
    const routes = ["/", "/modules", "/users", "/settings/tls", "/logs", "/maintenance"];
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (entry) => { if (entry.type() === "error") errors.push(entry.text()); });
    const result = [];
    for (const colorScheme of ["light", "dark"]) {
        await page.emulateMedia({colorScheme});
        for (const width of [360, 1366]) {
            await page.setViewportSize({width, height: 900});
            for (const route of routes) {
                const reply = await page.goto(origin + route);
                await page.keyboard.press("Tab");
                const state = await page.evaluate(() => ({
                    viewport: innerWidth,
                    content: document.documentElement.scrollWidth,
                    focus: document.activeElement.matches(":focus-visible"),
                    outline: getComputedStyle(document.activeElement).outlineStyle,
                    js: [...document.scripts].map((script) => new URL(script.src).pathname)
                }));
                if (!reply || reply.status() !== 200 || page.url() !== origin + route
                    || state.content > state.viewport || !state.focus || state.outline === "none"
                    || state.js.some((path) => /xterm|chart|graph/.test(path)))
                    throw new Error(JSON.stringify({route, colorScheme, width, status: reply?.status(), state}));
                result.push({route, colorScheme, width, ...state});
            }
        }
    }
    if (errors.length) throw new Error(JSON.stringify(errors));
    return {layouts: result.length, errors: errors.length, routes,
        maxOverflow: Math.max(...result.map((item) => item.content - item.viewport))};
}
