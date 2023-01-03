describe('Home page', () => {
    it('should redirect to okta without credentials', async () => {
        await browser.url(`/`);
        await expect(browser).toHaveUrlContaining('ouryahoo-qa.oktapreview.com');
    });
    it('should login with valid credentials', async () => {
        await browser.newUser();
        await browser.url(`/`);
        await expect(browser).toHaveUrlContaining('athenz.ouryahoo.com/');
    });
})
