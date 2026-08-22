# Releasing

Publishing is a maintainer's action, by hand, with multi-factor authentication,
from a trusted machine. **No credential that can publish this package exists in
this repository, and none should.**

## Why it is not automated

An npm automation token — the kind a workflow needs — is a bearer secret that
bypasses two-factor authentication *by design*: that is what makes it work
unattended, and exactly what makes it worth stealing. Anything that can read
the repository's secrets can publish — a compromised workflow, a malicious
build-time dependency, a pull request that edits a workflow file — and two
factors protecting the account mean nothing while a token beside it can
publish without them. So the trade is made deliberately and in the other
direction: this project gives up unattended releases, and npm provenance with
them, and keeps the property that publishing requires a human holding a second
factor.

The long form of that argument — what provenance would buy, and the trusted
publishing setting that could one day restore it without a stored secret —
lives with the codec, which made the same trade first:
[MetrologicalCBOR.TS/docs/releasing.md](https://github.com/Vanaheimr/MetrologicalCBOR.TS/blob/master/docs/releasing.md).

## What the tag workflow does, and what it does not

[`.github/workflows/tag.yml`](../.github/workflows/tag.yml) runs on a `v*`
tag. It has `contents: read` and no secrets at all, so it *cannot* publish. It
refuses the tag if it does not match the version in `package.json`, runs
`npm run verify` — both type-check views of `src/`, the build, and every test
including the bundle in its Node-free context — and rehearses the tarball with
`npm pack --dry-run`. It answers the question a maintainer has at exactly that
moment — *is the thing I just tagged good?* — and then stops, because the next
step is yours.

## Cutting one

Every line below runs on your machine. `0.2.0` stands for the version being
cut.

**Check what a release checks.**

```bash
npm run verify
```

**Set the version and cut the changelog.**

```bash
npm version 0.2.0 --no-git-tag-version
```

`--no-git-tag-version`, because the tag is made and signed below rather than
by npm. The version in `package.json` and the newest heading in
[../CHANGELOG.md](../CHANGELOG.md) must agree: the tag workflow compares the
tag against the first, and a reader compares it against the second. Move what
the release contains out of `[Unreleased]` and under the new heading while you
are there — and check what it holds before choosing the number: under 0.x,
behaviour changes make a minor, not a patch.

**Read the README as a stranger holding only the tarball.** npm renders the
README of the tarball it was handed and keeps it until the next version is
cut; a fix committed after the publish reaches GitHub and never the registry
page. Link relatively where the target ships — `dist/`, the licence, the
notice, the changelog — and absolutely where it does not, which is everything
under `src/` and `tests/`.

**Rehearse the tarball.**

```bash
npm pack --dry-run
```

Read the file list: `dist/`, README.md, LICENSE.md, NOTICE and CHANGELOG.md,
nothing else. 0.1.0 was 55 files and 171 kB packed — 0.8 MB unpacked, most of
it source maps.

**Tag it, push it, and let the tag workflow answer.**

```bash
git tag -s v0.2.0 -m "v0.2.0"
```

```bash
git push origin v0.2.0
```

A signed tag, because it is what the release is identified by — "npm carries
the bytes of this commit" is only a checkable claim while the tag still points
where it pointed when you published.

**Then, and only once that run is green, publish by hand.**

```bash
npm whoami
```

```bash
npm publish
```

npm asks for the second factor. `prepublishOnly` runs `verify` once more
before anything leaves the machine, and `publishConfig.access` is already
`public`, which a scoped package needs on its first publish.

Afterwards, check that what arrived is what you meant to send:

```bash
npm view @vanaheimr/cose version dist.fileCount dist.unpackedSize
```
