# How to contribute

First, thanks for taking the time to contribute to our project! There are many ways you can help out.

### Questions

If you have a question that needs an answer, [create an issue](https://help.github.com/articles/creating-an-issue/), and label it as a question.
Another option is to initiate a [discussion](https://github.com/AthenZ/athenz/discussions).

### Issues for bugs or feature requests

If you encounter any bugs in the code, or want to request a new feature or enhancement, please [create an issue](https://help.github.com/articles/creating-an-issue/) to report it. Kindly add a label to indicate what type of issue it is.

### Contribute Code

We ask that before contributing, please make the effort to coordinate with the maintainers of the project before submitting large or high 
impact PRs. This will prevent you from doing extra work that may or may not be merged.

While pull requests are the methodology for submitting changes to code, changes are much more likely to be accepted if they are accompanied by
additional engineering work. While we don't define this explicitly, most of these goals are accomplished through communication of the design 
goals and subsequent solutions. Often times, it helps to first state the problem before presenting solutions.

Typically, the best methods of accomplishing this are to submit an issue, stating the problem. This issue can include a problem statement and a
checklist with requirements. If solutions are proposed, alternatives should be listed and eliminated. Even if the criteria for elimination of 
a solution is frivolous, say so.

Make sure that new tests are added for bugs in order to catch regressions and tests with new features to exercise the new functionality that 
is added.

***Creating a Pull Request***

Please follow [best practices](https://github.com/trein/dev-best-practices/wiki/Git-Commit-Best-Practices) for creating git commits.

When your code is ready to be submitted, [submit a pull request](https://help.github.com/articles/creating-a-pull-request/) to begin the code review process.

## Sign your work

The sign-off is a simple line at the end of the explanation for the patch. Your
signature certifies that you wrote the patch or otherwise have the right to pass
it on as an open-source patch. The rules are pretty simple: if you can certify
the below (from [developercertificate.org](http://developercertificate.org/)):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
1 Letterman Drive
Suite D4700
San Francisco, CA 94129 USA

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Then you just add a line to every git commit message:

    Signed-off-by: Joe Smith <joe.smith@email.com>

Use your real name (sorry, no pseudonyms or anonymous contributions.)

If you set your `user.name` and `user.email` git configs, you can sign your
commit automatically with `git commit -s`.