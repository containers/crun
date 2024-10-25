# Contributing to crun

Thanks for your interest in contributing!

## Note: Before writing a big patch

If you plan to contribute a large change, please get in touch *before*
submitting a pull request by e.g. filing an issue describing your proposed
change. This will help ensure alignment.

## Background knowledge

You will need to understand the C programming language.

## Development environment

Crun at its core is a low-dependency C library and CLI tools. You'll
need a Linux environment, which could be a container or a VM/physical system.

crun should be buildable on nearly any relatively modern Linux OS/distribution.

### Building and testing

crun uses [GNU Autotools](https://www.gnu.org/software/automake/manual/html_node/Autotools-Introduction.html) for its build system. Ensure that Autotools is installed and properly configured on your system.

#### Setup

To set up the build, run the following commands in the root directory:

```bash
./autogen.sh
./configure --prefix=/usr
make -j $(nproc)
```


## Testing

To run the crun tests suite, you can use the following command:

```bash
make check
```

## Code linting

Be sure you've run
```
make clang-format
```

to reformat the code automatically.

## Submitting a patch

The podman project has some [generic useful guidance](https://github.com/containers/podman/blob/main/CONTRIBUTING.md#submitting-pull-requests);
like that project, a "Developer Certificate of Origin" is required.

### Sign your PRs

The sign-off is a line at the end of the explanation for the patch. Your
signature certifies that you wrote the patch or otherwise have the right to pass
it on as an open-source patch. The rules are simple: if you can certify
the below (from [developercertificate.org](https://developercertificate.org/)):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
660 York Street, Suite 102,
San Francisco, CA 94110 USA

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

### Git commit style

Please look at `git log` and match the commit log style, which is very
similar to the
[Linux kernel](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git).

Then you just add a line to every git commit message:

    Signed-off-by: Joe Smith <joe.smith@email.com>

Use your real name (sorry, no pseudonyms or anonymous contributions).

1. Title
    - Specify the context or category of the changes e.g. `lib` for library changes, `docs` for document changes, `bin/<command-name>` for command changes, etc.
    - Begin the title with the first letter of the first word capitalized.
    - Aim for less than 50 characters, otherwise 72 characters max.
    - Do not end the title with a period.
    - Use an [imperative tone](https://en.wikipedia.org/wiki/Imperative_mood).
2. Body
    - Separate the body with a blank line after the title.
    - Begin a paragraph with the first letter of the first word capitalized.
    - Each paragraph should be formatted within 72 characters.
    - Content should be about what was changed and why this change was made.
    - If your commit fixes an issue, the commit message should end with `Closes: #<number>`.

Commit Message example:

```bash
<context>: Less than 50 characters for subject title

A paragraph of the body should be within 72 characters.

This paragraph is also less than 72 characters.
```

For more information see [How to Write a Git Commit Message](https://chris.beams.io/posts/git-commit/)
