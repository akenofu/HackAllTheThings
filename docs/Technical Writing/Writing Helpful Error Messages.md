** Based on [Writing Helpful Error Messages - Google Developers](https://developers.google.com/tech-writing/error-messages)**
Data collected through Google support systems and UX research identified the following common problems with _bad_ error messages:

-   unactionable
-   vague
-   imprecise
-   confusing
-   inaccurate
-   unclear cause
-   unknown next steps

Conversely, _good_ error messages provide the following benefits:

-   Deliver the best user experience.
-   Are actionable.
-   Are universally accessible. (To learn more, take [Tech Writing for Accessibility.](https://developers.google.com/tech-writing/accessibility))
-   Enable users to help themselves.
-   Reduce the support workload.
-   Enable faster resolution of issues.

---

## General error handling rules

### Don't fail silently

Failure is inevitable; failing to report failures is inexcusable. Embrace your software's fallibility. Assume that humans will make mistakes using your software. Try to minimize ways for people to misuse your software, but assume that you can't completely eliminate misuse. Therefore, plan error messages as you design software.

### Follow the programming language guides
### Implement the full error model

### Avoid swallowing the root cause

API implementations should not swallow the root cause of issues occurring in the back end. For example, many different situations can cause a "Server error" problem, including:

-   service failure
-   network connection drop
-   mismatching status
-   permission issues

"Server error" is too general an error message to help users understand and fix the problem. If the server logs contain identification information about the in-session user and operation, we recommend providing additional context on the particular failure case.

### Log the error codes

Numeric **error codes** help customer support monitor and diagnose errors. Consequently, specifying numeric error codes along with textual error messages is often quite valuable.

You can specify error codes for both internal and external errors. For internal errors, provide a proper error code for easy lookup/debugging by internal support personnel and engineers.

Document all error codes.

### Raise errors immediately

Raise errors as early as useful. Holding on to errors and then raising them later increases debugging costs dramatically.

---

## Explain the proplem

### Identify the error's cause
Tell users exactly what went wrong. Be specific—vague error messages frustrate users.

### Identify the user's invalid inputs

If the error involves values that the user can enter or modify (for example, text, settings, command-line parameters), then the error message should identify the offending value(s).

❌ Not Recommended

> Funds can only be transferred to an account in the same country.

✅Recommended

> You can only transfer funds to an account within the same country. Sender account's country (UK) does not match the recipient account's country (Canada).

If the invalid input is a very long value that spans many lines, consider doing one of the following:

-   Disclose the bad input progressively; that is, provide one or more clickable ellipses to enable users to control how much additional error information they want to see.
-   Truncate the bad input, keeping only its essential parts.

### Specify requirements and constraints
Help users understand requirements and constraints. Be specific. Don't assume that users know the limitations of your system.

---
## Explain the solution

### Explain how to fix the proplem

Create **actionable error messages**. That is, after explaining the cause of the problem, explain how to fix the problem.

❌ Not Recommended

> The client app on your device is no longer supported.

✅Recommended

> The client app on your device is no longer supported. To update the client app, click the **Update app** button.

### Provide Examples

Supplement explanations with examples that illustrate how to correct the problem.

❌ Not Recommended

> Invalid email address.

✅Recommended

> The specified email address (robin) is missing an @ sign and a domain name. For example: robin@example.com.


## Write Clearley

### Avoid double negatives

A **double negative** is a sentence or phrase that contains two negative words, such as:

-   _not_, including contractions like _can't_, _won't_
-   _no_

Readers find double negatives hard to parse. ("Wait, do two negatives make a positive or is the author of the error message using two negatives to emphasize something I shouldn't do?") 

Similarly, Avoid exceptions to exceptions.

### Use terminology consistently

Use terminology consistently for all error messages within a single product area. If you call something a "datastore" in one error message, then call the same thing a "datastore" in all the other error messages.

❌ Not Recommended

> Can't connect to cluster at 127.0.0.1:56. Check whether minikube is running.

✅Recommended

> Can't connect to minikube at 127.0.0.1:56. Check whether minikube is running.


**Note:** Some authoring systems automatically recommend synonyms to ensure that you don't keep repeating the same word. Yes, variety spices up paragraphs. However, variety in error messages can confuse users.

Error messages must appear consistently with similar formats and non-contradictory content; that is, the same problem must generate the same error message. For example, if different parts of an app each detect problems with internet connection, both parts should emit the same error message.

### Format Error Messages
#### Link to more detailed documentation
When an error requires a lengthy explanation (for example, multiple sentences) and appropriate documentation is available, use links to redirect users to more detailed documentation.

### Use progressive disclosure
Some error messages are long, requiring a lot of text to explain the problem and solution. Unfortunately, users sometimes ignore long error messages, intimidated by the "wall of text." A good compromise is to display a briefer version of the error message and then give users the option to click something to get the full context.

❌ Not Recommended

> TextField widgets require a Material widget ancestor, but none were located. In material design, most widgets are conceptually “printed” on a sheet of material. To introduce a Material widget, either directly include one or use a widget that contains a material itself.

✅Recommended

> TextField widgets require a Material widget ancestor, but none were located.  
**...**(Click to see more.)  
  In material design, most widgets are conceptually "printed" on a sheet of material. To introduce a Material widget, either directly include one or use a widget that contains a material itself.

#### Place error messages close to the error
For coding errors, place error messages as close as possible to the place where the error occurred.

#### Handle font colors carefully
A surprising percentage of readers are color blind, so be careful with colors in error messages. 

Many forms of color blindness exist, so just avoiding a red/green combination isn't sufficient. Because you can't depend on all your users being comfortable with color, we recommend pairing color with another visual cue. 

A few ways to go around this:
- Pairs colors with boldface
- Pairs color with extra spaces
- Skip color completely

### Set the right tone

The tone of your error messages can have a significant effect on how your users interpret them.

#### Be Positive
Instead of telling the user what they did wrong, tell the user how to get it right.

❌ Not recommended

> You didn't enter a name.

✅ Recommended

> Enter a name.

❌ Not recommended

> You entered an invalid postal code.

✅ Recommended

> Enter a valid postal code. _[Explanation of valid postal code.]_

 ❌Not recommended

> ANSI C++ forbids declaration 'ostream' with no type 'ostream'.

✅ Recommended

> ANSI C++ requires a type for declaration 'ostream' with type 'ostream'.

#### Don't be overly apologetic
While maintaining positivity, avoid the words "sorry" or "please." Focus instead on clearly describing the problem and solution.

> **Note:** Different cultures interpret apologies differently. Some cultures expect apologies in certain situations; other cultures find apologies from software corporations somewhat insincere. Although this lesson suggests avoiding apologies, be aware of your target audience's expectations.


#### Avoid humor

Don't attempt to make error messages humorous. Humor in error messages can fail for the following reasons:

-   Errors frustrate users. Angry users are generally not receptive to humor.
-   Users can misinterpret humor. (Jokes don't always cross borders well.)
-   Humor can detract from the goal of the error message.

#### Don't blame the user
If possible, focus the error message on what went wrong rather than assigning blame.

❌ Not recommended

> You specified a printer that's offline.

✅ Recommended

> The specified printer is offline