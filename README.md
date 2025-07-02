# repctl - a  CLI for SysReptor

`repctl` is a CLI tool for [sysreptor](https://github.com/Syslifters/sysreptor/).

Note that there is the [reptor](https://github.com/Syslifters/reptor) CLI from the
creators of SysReptor which has a lot more features, but doesn't cover the specific
use-case the author faced. `repctl` might eventually catch up, but no
promises! 😜

## Brought to you by Mint Secure GmbH

This tool was developed during an internship at [Mint Secure](https://mint-secure.de).
Thanks for open-sourcing it!

## Configuration

`repctl` needs a SysReptor api-key to access your instance. You can pass it via 
`--api-key` to any command or set an `API_KEY` environment variable. To make this 
convenient, `repctl` loads environment variables from a `.env` file in the current 
working directory or from `~/.config/repctl.env`.

## Features / Use-Case / Motivation

At the moment `repctl` serves a very specific use-case:

[Finding Templates](https://docs.sysreptor.com/finding-templates/overview/)
are created from markdown files containing frontmatter.

These finding templates are used when automatically creating findings from tool
outputs. (For now, ScubaGear is the only supported tool, more to come in the
future).

## Loading templates

```sh
$ repctl load-templates --help
                                                                                                                                         
usage: repctl load-templates [-h] reptorurl input

positional arguments:
  reptorurl   BaseUrl of SysReptor Instance, e.g.: https://sysreptor.example.com
  input       Snippet file or directory containing snippets (searched recursively for .md files)

options:
  -h, --help  show this help message and exit
```

This is mostly interesting if you want to maintain your finding templates as code,
or you want to automate deriving finding templates from some other source. 
You can manually or programmatically prepare your finding templates as markdown
files with front matter - which we will hereafter call **snippet files** - and then load
(and update) them into SysReptor using `repctl`. Details on the format of these
markdown files will follow shortly.

### Prerequisites

You will need at least one SysReptor Design that defines a finding field called
`repctlTemplateId`. This is needed so `repctl` can correlate the finding template in
SysReptor with your markdown files when loading updates.

### Format of Snippets

Let's look at a snippet file:

```markdown
---
templateId: cve-2025-999   # Used to support updates and multiple languages 
lang: en-US   # Snippets with the same id are aggregated to support multiple languages 
isMain: true  
sysReptorFields: 
  reptorField1: 42
  reptorField2: true
title: The title of your Template
tags:
 - tag1
annotations:  # Dedicated space for your own metadata, repctl ignores this
  metaFiled: metadata
contentField: myDescription  # The markdown below is loaded into this field
---

## Hello World!

Markdown goes here !
```

Since are reading this, you are probably already familiar with SysReptor templates,
so much of the yaml fields in the front matter should make sense to you.

The more interesting parts are these:

If you load multiple snippet files with the same `templateId` simultaneously,
`repctl` will aggregate them into one finding template. There may only be one
snippet with `isMain` set to `true` and every language should of course only be used
once for any given `templateId`.

`repctl load-templates` will recursively scan for `.md` files when passed a directory!

The created / updated finding template will contain all fields in `sysReptorFields`, 
the `repctlTemplateId` field **and additionally a field with the key specified in
contentField**. The value of that field is the markdown body of the snippet. So our
example snippet would look like this when represented as json:

```json
{ 
    "reptorField1": 42,
    "reptorField2": true,
    "myDescription": "## Hello World\nMarkdown goes here!\n",
    "repctlTemplateField":"cve-2025-999-7ae1fdaa9ec020aa0a030c1135768d2012faf888"
}
```

> [!IMPORTANT]  
> Any fields you specify in your snippets must exist as finding fields in at least
> one design **before** loading them! Otherwise, SysReptor discards them.

## Loading ScubaGear findings into a SysReptor Project

```shell
$ repctl load-findings scubagear --help
usage: repctl load-findings scubagear [-h] [--lang LANG] project_url input

positional arguments:
  project_url  URL of the project on your SysReptor instance. (Simply copy it from your browser!)
  input        Input file: ScubaResults_<id>.json

options:
  -h, --help   show this help message and exit
  --lang LANG  Language code to use for templates, default: de-DE
```

Create a project in your SysReptor Instance and copy the url from your browser. It
doesn't matter in what exact part of the UI you are on, `repctl` parses the URL,
extracts the project id and extrapolates the api url for your instance.

Then all you have to do is pass the url and the `ScubaResults_<id>.json` from your
ScubaGear outputs.

> [!IMPORTANT]  
> You will need to create and load finding templates for all ScubaGear Policies and
> PolicyGroups before you can load a ScubaGear result. More Details below.

### Details for ScubaGear

#### Pseudo-Findings

The policies checked by ScubaGear policies are organized in groups. `repctl` creates
a "pseudo" finding for every group, which you can use to include information about
the policy group in your report. If no template with an appropriate `templateId`
exists, this step will be skipped.

#### templateIds

The ScubaGear loader expects to find a finding template with `templateId`  
`scubagear-<policy id>` for every policy checked by the ScubaGear scan, e.g.:  
`scubagear-MS.SHAREPOINT.4.2v1`.

For the group pseudo-findings, the expected `templateId` is:  
`scubagear-<lowercase product>-<group id>`, e.g.:  
`scubagear-powerplatform-3`.

#### Finding Fields

The ScubaGear loader populates the following fields, they are "added" and 
potentially override those you specified in your finding templates:

`criticality`, `result`, `details`

If you are familiar with ScubaGear, you should know what they mean.

## Implementation Details

### The `repctlTemplateId` field

SysReptor doesn't allow you to specify your own IDs for templates, The "real" ids are 
generated upon creation by the server. To allow `repctl` to find the right templates,
it leverages the "search" feature of the template API. It stores the `templateId` as 
this "special" field and uses it as the search query when updating or creating findings
from the template.

To avoid unfortunate collisions, like for example a chosen `templateId`
also appearing in a field of another template and thus making the search-result 
non-unique, `repctl` appends the sha1-hash of the `templateId` to itself before storing 
it as `repctlTemplateId`. When searching for a template id, it computes the hash again 
and submits it as the search query.

### Creating loaders for more tools

There is an interface for finding loaders in 
[repctl.findings](src/repctl/findings/__init__.py). Feel free to contribute. We 
might also add a full-blown plugin-interface at some point. 
