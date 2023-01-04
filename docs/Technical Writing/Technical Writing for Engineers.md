** Based on [Technical Writing for Engineers - Google Developers](https://developers.google.com/tech-writing)**

## Words

### Use acronyms properly

On the initial use of an unfamiliar acronym within a document or a section, spell out the full term, and then put the acronym in parentheses. Put both the spelled-out version and the acronym in boldface. For example:

> If no cache entry exists, the Mixer calls the **OttoGroup Server** (**OGS**) to fetch Ottos for the request. The OGS is a repository that holds all servable Ottos. The OGS is organized in a logical tree structure, with a root node and two levels of leaf nodes. The OGS root forwards the request to the leaves and collects the responses.

Do not cycle back-and-forth between the acronym and the expanded version in the same document.

Here are the guidelines for acronyms:
-   Don't define acronyms that would only be used a few times.
-   Do define acronyms that meet both of the following criteria:
-   The acronym is significantly shorter than the full term.
-   The acronym appears many times in the document.

### Use pronoun properly

Consider the following pronoun guidelines:
-   Place the pronoun as close as possible to the referring noun. In general, if more than five words separate your noun from your pronoun, consider repeating the noun instead of using the pronoun.
- If you introduce a second noun between your noun and your pronoun, reuse your noun instead of using a pronoun.

To help readers, avoid using this or that in ways where it's not clear what they refer to. Use either of the following tactics to clarify ambiguous uses of this and that:

- Replace this or that with the appropriate noun.
- Place a noun immediately after this or that.

---

## Active voice vs. Passive Voice

**The vast majority of sentences in technical writing should be in active voice.**

Putting the form of be and the past participle together yields passive verbs, such as the following:

- was interpreted
- is generated
- was formed
- is frozen

It is easy to mistakenly classify sentences starting with an imperative verb as passive. An **imperative verb** is a command. Many items in numbered lists start with imperative verbs. For example, _Open_ and _Set_ in the following list are both imperative verbs:

1.  Open the configuration file.
2.  Set the `Frombus` variable to `False`.

Sentences that start with an imperative verb are typically in active voice, even though they don't explicitly mention an actor. Instead, sentences that start with an imperative verb _imply_ an actor. The implied actor is **you**.

Distinguish active voice from passive voice in more complex sentences
Many sentences contain multiple verbs, some of which are active and some of which are passive. For example, the following sentence contains two verbs, both of which are in passive voice:

![](/Screenshots/Pasted%20image%2020221114134659.png)

Here is that same sentence, partially converted to active voice:
![](/Screenshots/Pasted%20image%2020221114134714.png)

And here is that same sentence, now fully converted to active voice:
![](/Screenshots/Pasted%20image%2020221114134728.png)

---
## Clear sentences

#### Choose Strong specific Verbs
To engage and educate readers, **choose precise, strong, specific verbs.** Reduce imprecise, weak, or generic verbs, such as the following:

-   forms of _be_: is, are, am, was, were, etc.
-   occur
-   happen

For example, consider how strengthening the weak verb in the following sentences ignites a more engaging sentence:

![](/Screenshots/Pasted%20image%2020221114135220.png)

Many writers rely on forms of _be_ as if they were the only spices on the rack. Sprinkle in different verbs and watch your prose become more appetizing. That said, a form of _be_ is sometimes the best choice of verb, so don't feel that you have to eliminate every form of _be_ from your writing.


Note that generic verbs often signal other ailments, such as:

-   an imprecise or missing actor in a sentence
-   a passive voice sentence

#### Reduce there is / there are
Sentences that start with **There is** or **There are** marry a generic noun to a generic verb. Generic weddings bore readers.

Removing **There is** replaces the generic subject with a better subject. For example, either of the following sentences is clearer than the original:

> A variable named `met_trick` stores the current accuracy.
> 
> The `met_trick` variable stores the current accuracy.

You can sometimes repair a **There is** or **There are** sentence by moving the true subject and true verb from the end of the sentence to the beginning. For example, notice that the pronoun **you** appears towards the end of the following sentence:

> There are two disturbing facts about Perl you should know.

Replacing **There are** with **You** strengthens the sentence:

> You should know two disturbing facts about Perl.

In other situations, writers start sentences with **There is** or **There are** to avoid the hassle of creating true subjects or verbs. If no subject exists, consider creating one. For example, the following **There is** sentence does not identify the receiving entity:

> There is no guarantee that the updates will be received in sequential order.

Replacing "There is" with a meaningful subject (such as **clients**) creates a clearer experience for the reader:

> Clients might not receive the updates in sequential order.


#### Minimize certain adjectives and adverbs
Granted, **screamingly fast** gets readers' attention but not necessarily in a good way. Feed your technical readers factual data instead of marketing speak. Refactor amorphous adverbs and adjectives into objective numerical information. For example:

> Setting this flag makes the application run 225-250% faster.

Note: Don't confuse educating your readers (technical writing) with publicizing or selling a product (marketing writing). When your readers expect education, provide education; don't intersperse publicity or sales material inside educational material.

---
## Short Sentences

**Focus each sentence on a single idea**, thought, or concept. Just as statements in a program execute a single task, sentences should execute a single idea. For example, the following very long sentence contains multiple thoughts:

> The late 1950s was a key era for programming languages because IBM introduced Fortran in 1957 and John McCarthy introduced Lisp the following year, which gave programmers both an iterative way of solving problems and a recursive way.

Breaking the long sentence into a succession of single-idea sentences yields the following result:

> The late 1950s was a key era for programming languages. IBM introduced Fortran in 1957. John McCarthy invented Lisp the following year. Consequently, by the late 1950s, programmers could solve problems iteratively or recursively.

### Convert some long sentences to lists

When you see the conjunction **or** in a long sentence, consider refactoring that sentence into a bulleted list. When you see an embedded list of items or tasks within a long sentence, consider refactoring that sentence into a bulleted or numbered list.

#### Eliminate or reduce extraneous words
Many sentences contain filler—textual junk food that consumes space without nourishing the reader. For example, see if you can spot the unnecessary words in the following sentence:

> An input value greater than 100 causes the triggering of logging.

Replacing **causes the triggering of** with the much shorter verb **triggers** yields a shorter sentence:

> An input value greater than 100 triggers logging.

The following table suggests replacements for a few common bloated phrases:

![](/Screenshots/Pasted%20image%2020221114155030.png)


### Reduce subordinate clauses

A **clause** is an independent logical fragment of a sentence, which contains an actor and an action. Every sentence contains the following:

-   a main clause
-   zero or more subordinate clauses

Subordinate clauses modify the idea in the main clause. As the name implies, subordinate clauses are less important than the main clause. For example, consider the following sentence:

> Python is an interpreted programming language, which was invented in 1991.
> 
> -   main clause: Python is an interpreted programming language
> -   subordinate clause: which was invented in 1991

You can usually identify subordinate clauses by the words that introduce them. The following list (by no means complete) shows common words that introduce subordinate clauses:

-   which
-   that
-   because
-   whose
-   until
-   unless
-   since

When editing, scrutinize subordinate clauses. Keep the `one sentence = one idea`, [single-responsibility principle](https://en.wikipedia.org/wiki/Single-responsibility_principle) in mind. Do the subordinate clauses in a sentence _extend_ the single idea or do they _branch off_ into a separate idea? If the latter, consider dividing the offending subordinate clause(s) into separate sentences.

### Distinguish that from which

**That** and **which** both introduce subordinate clauses. What's the difference between them? Well, in some countries, the two words are pretty much interchangeable. Inevitably though, alert readers from the United States will angrily announce that you confused the two words again.

In the United States, reserve **which** for nonessential subordinate clauses, and use **that** for an essential subordinate clause that the sentence can't live without. For example, the key message in the following sentence is that Python is an interpreted language; the sentence can survive without _Guido van Rossum invented_:

> Python is an interpreted language, **which** Guido van Rossum invented.

By contrast, the following sentence requires _don't involve linear algebra_:

> Fortran is perfect for mathematical calculations **that** don't involve linear algebra.

If you read a sentence aloud and hear a pause just before the subordinate clause, then use **which**. If you don't hear a pause, use **that**. Go back and read the preceding two example sentences. Do you hear the pause in the first sentence?

Place a comma before **which**; do not place a comma before **that**.

---
## Lists and tables
Good lists can transform technical chaos into something orderly. Technical readers generally love lists. Therefore, when writing, seek opportunities to convert prose into lists.

#### Choose the correct type of list
Use a **bulleted list** for _unordered_ items; use a **numbered list** for _ordered_ items. In other words:

-   If you rearrange the items in a _bulleted_ list, the list's meaning does not change.
-   If you rearrange the items in a _numbered_ list, the list's meaning _changes_.

#### Convert Embedded lists to bulleted or numbered lists
An **embedded list** (sometimes called a **run-in** list) contains items stuffed within a sentence. For example, the following sentence contains an embedded list with four items.

> The llamacatcher API enables callers to create and query llamas, analyze alpacas, delete vicugnas, and track dromedaries.

Generally speaking, embedded lists are a poor way to present technical information. Try to transform embedded lists into either bulleted lists or numbered lists.

### Keep list items parallel

All items in a **parallel** list look like they "belong" together. That is, all items in a parallel list match along the following parameters:

-   grammar
-   logical category
-   capitalization
-   punctuation

### Start numbered list items with imperative verbs
Consider starting all items in a numbered list with an imperative verb. An **imperative verb** is a command, such as **open** or **start**.

e.g.

1.  Download the Frambus app from Google Play or iTunes.
2.  Configure the Frambus app's settings.
3.  Start the Frambus app.

### Punctuate items appropriately
If the list item is a sentence, use sentence capitalization and punctuation. Otherwise, do not use sentence capitalization and punctuation. For example, the following list item is a sentence, so we capitalized the **M** in **Most** and put a period at the end of the sentence:

-   Most carambolas have five ridges.

However, the following list item is not a sentence, so we left the **t** in **the** in lowercase and omitted a period:

-   the color of lemons

### Create useful tables
Analytic minds tend to love tables. Given a page containing multiple paragraphs and a single table, engineers' eyes zoom towards the table.

Consider the following guidelines when creating tables:

-   Label each column with a meaningful header. Don't make readers guess what each column holds.
-   Avoid putting too much text into a table cell. If a table cell holds more than two sentences, ask yourself whether that information belongs in some other format.
-   Although different columns can hold different types of data, strive for parallelism _within_ individual columns. For instance, the cells within a particular table column should not be a mixture of numerical data and famous circus performers.

### Introduce each list and table
We recommend introducing each list and table with a sentence that tells readers what the list or table represents. In other words, give the list or table context. Terminate the introductory sentence with a colon rather than a period.

Although not a requirement, we recommend putting the word **following** into the introductory sentence. For example, consider the following introductory sentences:

> The following list identifies key performance parameters:
> 
> Take the following steps to install the Frambus package:
> 
> The following table summarizes our product's features against our key competitors' features:

---

## Paragraphs

> The work of writing is _simply_ this: untangling the dependencies among the parts of a topic, and presenting those parts in a logical stream that enables the reader to understand you.

#### Write a great opening sentence

The opening sentence is the most important sentence of any paragraph. Busy readers focus on opening sentences and sometimes skip over subsequent sentences. Therefore, focus your writing energy on opening sentences.

Good opening sentences establish the paragraph's central point. For example, the following paragraph features an effective opening sentence:

> A loop runs the same block of code multiple times. For example, suppose you wrote a block of code that detected whether an input line ended with a period. To evaluate a million input lines, create a loop that runs a million times.

The preceding opening sentence establishes the theme of the paragraph as an introduction to loops. By contrast, the following opening sentence sends readers in the wrong direction:

> A block of code is any set of contiguous code within the same function. For example, suppose you wrote a block of code that detected whether an input line ended with a period. To evaluate a million input lines, create a loop that runs a million times.


#### Focus each paragraph on a single topic
A paragraph should represent an independent unit of logic. Restrict each paragraph to the current topic. Don't describe what will happen in a future topic or what happened in a past topic. When revising, ruthlessly delete (or move to another paragraph) any sentence that doesn't directly relate to the current topic.

#### Don't make paragraphs too long or too short
Long paragraphs are visually intimidating. _Very_ long paragraphs form a dreaded "wall of text" that readers ignore. Readers generally welcome paragraphs containing three to five sentences, but will avoid paragraphs containing more than about seven sentences. When revising, consider dividing very long paragraphs into two separate paragraphs.

Conversely, don't make paragraphs too short. If your document contains plenty of one-sentence paragraphs, your organization is faulty. Seek ways to combine those one-sentence paragraphs into cohesive multi-sentence paragraphs or possibly into lists.


#### Answer what, why, and how

Good paragraphs answer the following three questions:

1.  **What** are you trying to tell your reader?
2.  **Why** is it important for the reader to know this?
3.  **How** should the reader use this knowledge? Alternatively, how should the reader know your point to be true?

For example, the following paragraph answers what, why, and how:
![](/Screenshots/Pasted%20image%2020221127231859.png)
---

## Audience

> good documentation = knowledge and skills your audience needs to do a task − your audience's current knowledge and skills 

In other words, make sure your document provides the information that your Audience needs but doesn't already have. Therefore, this unit explains how to do the following:

-   Define your audience.
-   Determine what your audience needs to learn.
-   Fit documentation to your audience.

### Define your audience
Begin by identifying your audience's **role**(s). Sample roles include:

-   software engineers
-   technical, non-engineer roles (such as technical program managers)
-   scientists
-   professionals in scientific fields (for example, physicians)
-   undergraduate engineering students
-   graduate engineering students
-   non-technical positions

Writing would be so much easier if everyone in the same role shared exactly the same knowledge. Unfortunately, knowledge within the same role quickly diverges. Amal is an expert in Python, Sharon's expertise is C++, and Micah's is in Java. Kara loves Linux, but David only knows iOS

Roles, by themselves, are insufficient for defining an audience. That is, you must also consider your audience's _proximity_ to the knowledge. The software engineers in Project Frombus know something about related Project Dingus but nothing about unrelated Project Carambola. The average heart specialist knows more about ear problems than the average software engineer but far less than an audiologist.

Time also affects proximity. Almost all software engineers, for example, studied calculus. However, most software engineers don't use calculus in their jobs, so their knowledge of calculus gradually fades. Conversely, experienced engineers typically know vastly more about their current project than new engineers on the same project.

#### Determine what your audience needs to learn
Write down a list of everything your target audience needs to learn to accomplish goals. In some cases, the list should hold tasks that the target audience needs to _perform_. For example:

> After reading the documentation, the audience will know how to do the following tasks:

> -   Use the Zylmon API to list hotels by price.
> -   Use the Zylmon API to list hotels by location.
> -   Use the Zylmon API to list hotels by user ratings.

If you are writing a design spec, then your list should focus on information your target audience should learn rather than on mastering specific tasks: For example:

> After reading the design spec, the audience will learn the following:

> -   Three reasons why Zylmon outperforms Zyljeune.
> -   Five reasons why Zylmon consumed 5.25 engineering years to develop.


### Fit documentation to your audience

#### Vocabulary and concepts
Be mindful of proximity. The people on your team probably understand your team's abbreviations, but do people on other teams understand those same abbreviations? As your target audience widens, assume that you must explain more.

Similarly, experienced people on your software team probably understand the implementation details and data structures of your team's project, but nearly everyone else (including new members of your team) does not. Unless you are writing specifically for other experienced members of your team, you typically must explain more than you expect.

#### Simple words
prefer simple words over complex words; avoid obsolete or overly-complex English words.

#### Cultural neutrality and idioms
**Idioms** are phrases whose overall meaning differs from the literal meaning of the individual words in that phrase. For example, the following phrases are idioms:

-   a piece of cake
-   Bob's your uncle

Cake? Bob? Most readers from the United States recognize the first idiom; most British readers recognize the second idiom. If you are writing strictly for a British audience, then _Bob's your uncle_ can be fine. However, if you are writing for an international audience, then replace that idiom with _this task is done_.

Idioms are so deeply ingrained in our speech that the special nonliteral meaning of idioms becomes invisible to us. That is, idioms are another form of the curse of knowledge.

Note that some people in your audience use translation software to read your documentation. Translation software tends to struggle more with cultural references and idioms than with plain, simple English.

---
## Documents

### State your document's scope

A good document begins by defining its scope. For example:

> This document describes the design of Project Frambus.

A better document additionally defines its non-scope—the topics not covered that the target audience might reasonably expect your document to cover. For example:

> This document does not describe the design for the related technology, Project Froobus.

Scope and non-scope statements benefit not only the reader but also the writer (you). While writing, if the contents of your document veer away from the scope statement (or venture _into_ the non-scope statement), then you must either refocus your document or modify your scope statement. When reviewing your first draft, delete any sections that don't help satisfy the scope statement.

### State your audience

A good document explicitly specifies its audience. For example:

> This document is aimed at the following audiences:
> 
> -   software engineers
> -   program managers

Beyond the audience's role, a good audience declaration might also specify any prerequisite knowledge or experience. For example:

> This document assumes that you understand matrix multiplication and the fundamentals of backpropagation.

In some cases, the audience declaration should also specify prerequisite reading or coursework. For example:

> You must read "Project Froobus: A New Hope" prior to reading this document.

### Summarize key points at the start
Engineers and scientists are busy people who won't necessarily read all 76 pages of your design document. Imagine that your peers might only read the first paragraph of your document. Therefore, ensure that the start of your document answers your readers' essential questions.

Professional writers focus considerable energy on page one to increase the odds of readers making it to page two. However, the start of any long document is the hardest page to write. Be prepared to revise page one many times.

### Compare and contrast
In your career, no matter how creative you are, you will author precious few documents containing truly revolutionary ideas. Most of your work will be evolutionary, building on existing technologies and concepts. Therefore, compare and contrast your ideas with concepts that your audience already understands. For example:

> The Froobus API handles the same use cases as the Frambus API, except that the Froobus API is much easier to use.

### Write for your audience

#### Define your audience's needs

Answering the following questions helps you determine what your document should contain:

-   Who is your target audience?
-   What is your target audience's goal? Why are they reading this document?
-   What do your readers already know _before_ they read your document?
-   What should your readers know or be able to do _after_ they read your document?

#### Organize the document to meet your audience's needs

---
## Punctuation

As a guideline, insert a comma wherever a reader would naturally pause somewhere within a sentence. For the musically inclined, if a period is a whole note rest, then a comma is perhaps a half-note or quarter-note rest. In other words, the pause for a comma is shorter than that for a period. For example, if you read the following sentence aloud, you probably rest briefly before the word _just_:

> C behaves as a mid-level language, just a couple of steps up in abstraction from assembly language.

You can also wedge a quick definition or digression between a pair of commas as in the following example:

> Python, an easy-to-use language, has gained significant momentum in recent years.

Finally, avoid using a comma to paste together two independent thoughts. For example, the comma in the following sentence is guilty of a punctuation felony called a **comma splice**:

❌ Not recommended

> Samantha is a wonderful coder, she writes abundant tests.

Use a period rather than a comma to separate two independent thoughts. For example:

✅ Recommended

> Samantha is a wonderful coder. She writes abundant tests.

For an example of emplyoing commas in senstences, check out the following link:
https://developers.google.com/tech-writing/one/punctuation#exercise

### Semicolons

A period separates distinct thoughts; a semicolon unites highly related thoughts. For example, notice how the semicolon in the following sentence unites the first and second thoughts:

✅ Recommended

> Rerun Frambus after updating your configuration file; don't rerun Frambus after updating existing source code.

Before using a semicolon, ask yourself whether the sentence would still make sense if you flipped the thoughts to opposite sides of the semicolon. For example, reversing the earlier example still yields a _valid_ sentence:

> Don't rerun Frambus after updating existing source code; rerun Frambus after updating your configuration file.

The thoughts preceding and following the semicolon must each be grammatically complete sentences. For example, the following semicolon is _incorrect_ because the passage following the semicolon is a [clause](https://developers.google.com/tech-writing/one/short-sentences#reduce_subordinate_clauses_optional), not a complete sentence:

❌ Not recommended

> Rerun Frambus after updating your configuration file; not after updating existing source code.

✅ Recommended

> Rerun Frambus after updating your configuration file, not after updating existing source code.

You should almost always use commas, not semicolons, to separate items in an embedded list. For example, the following use of semicolons is _incorrect_:

❌ Not recommended

> Style guides are bigger than the moon; more essential than oxygen; and completely inscrutable.

As mentioned earlier in this lesson, technical writing usually prefers bulleted lists to embedded lists. However, if you truly prefer an embedded list, use commas rather than semicolons to separate the items, as in the following example:

✅ Recommended

> Style guides are bigger than the moon, more essential than oxygen, and completely inscrutable.

Many sentences place a transition word or phrase immediately after the semicolon. In this situation, place a comma after the transition. Note the comma after the transition in the following two examples:

> Frambus provides no official open source package for string manipulation; however**,** subsets of string manipulation packages are available from other open source projects.

> Even seemingly trivial code changes can cause bugs; therefore**,** write abundant unit tests.


### Em dashes

![](/Screenshots/Pasted%20image%2020221128001440.png)

Em dashes are compelling punctuation marks, rich with punctuation possibilities. An em dash represents a longer pause—a bigger break—than a comma. If a comma is a quarter note rest, then an em dash is a half-note rest. For example:

> C++ is a rich language—one requiring extensive experience to fully understand.

Writers sometimes use a pair of em dashes to block off a digression, as in the following example:

> **Protocol Buffers**—often nicknamed **protobufs**—encode structured data in an efficient yet extensible format.

Could we have used commas instead of em dashes in the preceding examples? Sure. Why did we choose an em dash instead of a comma? Feel. Art. Experience.

> The [Google Style Guide](https://developers.google.com/style/dashes#en-dashes)recommends avoiding en dashes (–).

### Parentheses

Use parentheses to hold minor points and digressions. Parentheses inform readers that the enclosed text isn't critical. Because the enclosed text isn't critical, some editors feel that text that deserves parentheses doesn't deserve to be in the document. As a compromise, keep parentheses to a minimum in technical writing.

The rules regarding periods and parentheses aren't always clear. Here are the standard rules:

-   If a pair of parentheses holds an entire sentence, the period goes inside the closing parenthesis.
-   If a pair of parentheses ends a sentence but does not hold the entire sentence, the period goes just outside the closing parenthesis.

For example:

> (Incidentally, Protocol Buffers make great birthday gifts.)
> 
> Binary mode relies on the more compact native form (described later in this document).

---

## Self-editing

### Adopt a style guide

Companies, organizations, and large open source projects frequently either adopt an existing style guide for their documentation or write their own. Many of the documentation projects on the [Google Developers](https://developers.google.com/) site follow the [Google Developer Documentation Style Guide](https://developers.google.com/style).

### Think like your audience
Who is your audience? Step back and try to read your draft from their point of view. Make sure the purpose of your document is clear, and provide definitions for any terms or concepts that might be unfamiliar to your readers.

It can be helpful to outline a persona for your audience. A persona can consist of any of the following attributes:

-   A role, such as _Systems Engineer_ or _QA Tester_.
-   An end goal, such as _Restore the database_.
-   A set of assumptions about the persona and their knowledge and experience. For example, you might assume that your persona is:
    -   Familiar with Python.
    -   Running a Linux operating system.
    -   Comfortable following instructions for the command line.

Note that relying too heavily on a persona (or two) can result in a document that is too narrowly focused to be useful to the majority of your readers.

### Read it out loud

To check if your writing is conversational, read it out loud. Listen for awkward phrasing, too-long sentences, or anything else that doesn't feel natural. Alternatively, consider using a screen reader to voice the content for you.

### Come back to it later

After you write your first draft (or second or third), set it aside. Come back to it after an hour (or two or three) and try to read it with fresh eyes. You'll almost always notice something that you could improve.

### Find a peer editor
Just as engineers need peers to review their code, writers need editors to give them feedback on docs. Ask someone to review your document and give you specific, constructive comments. Your peer editor doesn't need to be a subject matter expert on the technical topic of your document, but they do need to be familiar with the style guide you follow.

---
## Organizing large documents

How do you organize a large collection of information into a cohesive document or website? Alternatively, how do you reorganize an existing messy document or website into something approachable and useful? The following tactics can help:

-   Choosing to write a single, large document or a set of documents
-   Organizing a document
-   Adding navigation
-   Disclosing information progressively

### When to write large documents

You can organize a collection of information into longer standalone documents or a set of shorter interconnected documents. A set of shorter interconnected documents is often published as a website, wiki, or similar structured format.

So, should you organize your material into a single document or into a set of documents in a website? Consider the following guidelines:

-   How-to guides, introductory overviews, and conceptual guides often work better as shorter documents when aimed at readers who are new to the subject matter. For example, a reader who is completely new to your subject matter might struggle to remember lots of new terms, concepts, and facts. Remember that your audience might be reading your documentation to gain a quick and general overview of the topic.
-   In-depth tutorials, best practice guides, and command-line reference pages can work well as lengthier documents, especially when aimed at readers who already have some experience with the tools and subject matter.
-   A great tutorial can rely on a narrative to lead the reader through a series of related tasks in a longer document. However, even large tutorials can sometimes benefit from being broken up into smaller parts.
-   Many longer documents aren't designed to be read in one sitting. For example, users typically scan through a reference page to search for an explanation of a command or flag.

### Organize a document
This section suggests some techniques for planning a longer document, including creating an outline and drafting an introduction. After you've completed the first draft of a document, you can review it against your outline and introduction to make sure you haven't missed anything you originally intended to cover.

#### Outline a document
Starting with a structured, high-level outline can help you group topics and determine where more detail is needed. The outline helps you move topics around before you get down to writing.

You might find it useful to think of an outline as the narrative for your document. There is no standard approach to writing an outline, but the following guidelines provide practical tips you might find useful:

-   Before you ask your reader to perform a task, explain to them why they are doing it. For example, the following bullet points illustrate a section of an outline from a tutorial about auditing and improving the accessibility of web pages:
    -   Introduce a browser plugin that audits the accessibility of web pages; explain that the reader will use the results of the audit report to fix several bugs.
    -   List the steps to run the plugin and audit the accessibility of a web page.
-   Limit each step of your outline to describing a concept or completing a specific task.
-   Structure your outline so that your document introduces information when it's most relevant to your reader. For example, your reader probably doesn't need to know (or want to know) about the history of the project in the introductory sections of your document when they're just getting started with the basics. If you feel the history of the project is useful, then include a link to this type of information at the end of your document.
-   Consider explaining a concept and then demonstrating how the reader can apply it either in a sample project or in their own work. Documents that alternate between conceptual information and practical steps can be a particularly engaging way to learn.
-   Before you start drafting, share the outline with your contributors. Outlines are especially useful if you're working with a team of contributors who are going to review and test your document.

#### Introduce a document
If readers of your documentation can't find relevance in the subject, they are likely to ignore it. To set the ground rules for your users, we recommend providing an introduction that includes the following information:

-   What the document covers.
-   What prior knowledge you expect readers to have.
-   What the document doesn't cover.

Remember that you want to keep your documentation easy to maintain, so don't try to cover everything in the introduction.

After you've completed the first draft, check your entire document against the expectations you set in your overview. Does your introduction provide an accurate overview of the topics you cover? You might find it useful to think of this review as a form of documentation quality assurance (QA).

### Add navigation
#### Prefer task-based headings
Choose a heading that describes the task your reader is working on. Avoid headings that rely on unfamiliar terminology or tools. For example, suppose you are documenting the process for creating a new website. To create the site, the reader must initialize the Froobus framework. To initialize the Froobus framework, the reader must run the `carambola` command-line tool. At first glance, it might seem logical to add either of the following headings to the instructions:

-   Running the carambola command
-   Initializing the Froobus framework

Unless your readers are already very experienced with the terminology and concepts for this topic, a more familiar heading might be preferable, such as _Creating the site_.

#### Provide text under each heading

Most readers appreciate at least a brief introduction under each heading to provide some context. Avoid placing a level three heading immediately after a level two heading, as in the following example:


```
## Creating the site
### Running the carambola command
```
 
In this example, a brief introduction can help orient the reader:

```
## Creating the site

To create the site, you run the `carambola` command-line tool. The command
displays a series of prompts to help you configure the site.

### Running the carambola command
```

### Disclose information progressively

Learning new concepts, ideas, and techniques can be a rewarding experience for many readers who are comfortable reading through documentation at their own pace. However, being confronted with too many new concepts and instructions too quickly can be overwhelming. Readers are more likely to be receptive to longer documents that progressively disclose new information to them when they need it. The following techniques can help you incorporate progressive disclosure in your documents:

-   Where possible, try introducing new terminology and concepts near to the instructions that rely on them.
-   Break up large walls of text. To avoid multiple large paragraphs on a single page, aim to introduce tables, diagrams, lists, and headings where appropriate.
-   Break up large series of steps. If you have a particularly long list of complicated steps, try to re-arrange them into shorter lists that explain how to complete sub-tasks.
-   Start with simple examples and instructions, and add progressively more interesting and complicated techniques. For example, in a tutorial for creating forms, start by explaining how to handle text responses, and then introduce other techniques to handle multiple choice, images, and other response types.

---
## Illustrating
Providing any graphics—good or bad—makes readers like the document more; however, only _instructive_ graphics help readers learn. This unit suggests a few ways to help you create figures truly worth a thousand words.

### Write the caption first
It is often helpful to write the caption _before_ creating the illustration. Then, create the illustration that best represents the caption. This process helps you to check that the illustration matches the goal.

Good captions have the following characteristics:

-   They are **brief**. Typically, a caption is just a few words.
-   They explain the **takeaway**. _After viewing this graphic, what should the reader remember?_
-   They **focus** the reader's attention. Focus is particularly important when a photograph or diagram contains a lot of detail.

### Constrain the amount of information in a single drawing
highly complex technical illustrations like the following tend to discourage most readers.
![](/Screenshots/Pasted%20image%2020221128105131.png)

Just as you avoid overly-long sentences, strive to avoid visual run-ons. As a rule of thumb, don't put more than one paragraph's worth of information in a single diagram. (An alternative rule of thumb is to avoid illustrations that require more than five bulleted items to explain.) I can hear you saying, "But real-life technical systems can be vastly more complex than the one shown in Figure 3." You are correct, but you probably don't feel compelled to explain real-life complex systems in a single paragraph.

The trick to reducing visual clutter into something coherent and helpful is to organize complex systems into subsystems, like those shown in the following figure:

![](/Screenshots/Pasted%20image%2020221128105146.png)
After showing the "big picture," provide separate illustrations of each subsystem.
![](/Screenshots/Pasted%20image%2020221128105212.png)

### Focus the reader's attention
When confronted with a complex screenshot like the following, readers struggle to determine what's relevant:

![](/Screenshots/Pasted%20image%2020221128105341.png)

Adding a visual cue, for example, the red oval in the following figure, helps readers focus on the relevant section of the screenshot:

![](/Screenshots/Pasted%20image%2020221128105358.png)

**Callouts** provide another way to focus the reader's attention. For pictures and line art, a callout helps our eyes find just the right spot to land on. Callouts in pictures are often better than paragraph long explanations of the pictures because callouts focus the reader's attention on the most important aspects of the picture. Then, in your explanation, you can focus directly on the relevant part of the diagram, rather than spending time describing what part of the image you are talking about.

In the example image, the callout and arrow quickly direct the reader to the purpose.

![](/Screenshots/Pasted%20image%2020221128105435.png)

### Illustrating is re-illustrating

As with writing, the first draft of an illustration is seldom good enough. Revise your illustrations to clarify the content. As you revise, ask yourself the following questions:

-   How can I simplify the illustration?
-   Should I split this illustration into two or more simpler illustrations?
-   Is the text in the illustration easy to read? Does the text contrast sufficiently with its background?
-   What's the takeaway?

For practical examples on iterating over illustrations, checkout: https://developers.google.com/tech-writing/two/illustrations#exercise_2 


### Illustration tools

There are many options available for creating diagrams. Three options that are free or have free options include:

-   [Google Drawings](https://drawings.google.com/)
-   [diagrams.net](https://diagrams.net/)
-   [LucidChart](https://www.lucidchart.com/pages/)

When exporting diagrams from these tools to use in documentation, it is usually best to export the files as [Scalable Vector Graphics](https://wikipedia.org/wiki/Scalable_Vector_Graphics) (SVG). The SVG format easily scales diagrams based on space constraints so that no matter the size, you end up with a high quality image.

---

## Creating Sample Code

Good samples are **correct** and **concise** code that your readers can **quickly understand** and **easily reuse** with **minimal side effects**.

### Correct
Sample code should meet the following criteria:

-   Build without errors.
-   Perform the task it claims to perform.
-   Be as production-ready as possible. For example, the code shouldn't contain any security vulnerabilities.
-   Follow language-specific conventions.

Sample code is an opportunity to directly influence how your users write code. Therefore, sample code should set the best way to use your product. If there is more than one way to code the task, code it in the manner that your team has decided is best. If your team hasn't considered the pros and cons of each approach, take time to do so.

Always test your sample code. Over time, systems change and your sample code may break. Be prepared to test and maintain sample code as you would any other code.

Many teams reuse their unit tests as sample programs, which is sometimes a bad idea. The primary goal of a unit test is to test; the only goal of a sample program is to educate.

A **snippet** is a piece of a sample program, possibly only one or a few lines long. Snippet-heavy documentation often degrades over time because teams tend not to test snippets as rigorously as full sample programs.

### Running sample code

Good documents explain how to run sample code. For example, your document might need to tell users to perform activities such as the following prior to running the samples:

-   Install a certain library.
-   Adjust the values assigned to certain environment variables.
-   Adjust something in the integrated development environment (IDE).

Users don't always perform the preceding activities properly. In some situations, users prefer to run or (experiment with) sample code directly in the documentation. ("Click here to run this code.")

Writers should consider describing the expected output or result of sample code, especially for sample code that is difficult to run.

### Concise
Sample code should be short, including only essential components. When a novice C programmer wants to learn how to call the `malloc` function, give that programmer a brief snippet, not the entire Linux source tree. Irrelevant code can distract and confuse your audience. That said, never use bad practices to shorten your code; always prefer correctness over conciseness.

### Understandable
Follow these recommendations to create clear sample code:

-   Pick descriptive class, method, and variable names.
-   Avoid confusing your readers with hard-to-decipher programming tricks.
-   Avoid deeply nested code.
-   Optional: Use bold or colored font to draw the reader's attention to a specific section of your sample code. However, use highlighting judiciously—too much highlighting means the reader won't focus on anything in particular.

### Commented

Consider the following recommendations about comments in sample code:

-   Keep comments short, but always prefer clarity over brevity.
-   Avoid writing comments about _obvious_ code, but remember that what is obvious to you (the expert) might not be obvious to newcomers.
-   Focus your commenting energy on anything non-intuitive in the code.
-   When your readers are very experienced with a technology, don't explain _what_ the code is doing, explain _why_ the code is doing it.

Should you place descriptions of code inside code comments or in text (paragraphs or lists) outside of the sample code? Note that readers who copy-and-paste a snippet gather not only the code but also any embedded comments. So, put any descriptions that belong in the pasted code into the code comments. By contrast, when you must explain a lengthy or tricky concept, you should typically place the text before the sample program.

> **Note:** If you must sacrifice production readiness in order to make the code shorter and easier to understand, explain your decisions in the comments.

### Reusable

For your reader to easily reuse your sample code, provide the following:

-   All information necessary to run the sample code, including any dependencies and setup.
-   Code that can be extended or customized in useful ways.

Having easy-to-understand sample code that's concise and compiles is a great start. If it blows up your reader's app, though, they won't be happy. Therefore, when writing sample code, consider any potential side effects caused by your code being integrated into another program. Nobody wants insecure or grossly inefficient code.

### The example and the anti-example
In addition to showing readers _what to do_, it is sometimes wise to show readers _what not to do_.

### Sequenced
A good sample code set demonstrates a range of complexity.

Readers completely unfamiliar with a certain technology typically crave simple examples to get started. The first and most basic example in a sample code set is usually termed a Hello World program. After mastering the basics, engineers want more complex programs. A good set of sample code provides a healthy range of simple, moderate, and complex sample programs.

