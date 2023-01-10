describe('Home page', () => {
    it('should redirect to okta without credentials', async () => {
        await browser.url(`/`);
        await expect(browser).toHaveUrlContaining('okta');
    });
    it('should login with valid credentials', async () => {
        await browser.newUser();
        await browser.url(`/`);
        await expect(browser).toHaveUrlContaining('athenz');
    });
})
