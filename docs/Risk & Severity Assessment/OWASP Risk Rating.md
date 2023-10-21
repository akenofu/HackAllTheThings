## OWASP Risk Rating Methodology
[OWASP Risk Rating Methodology | OWASP Foundation](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)

Let’s start with the standard risk model:
**Risk = Likelihood * Impact**

In the sections below, the factors that make up “likelihood” and “impact” for application security are broken down. The tester is shown how to combine them to determine the overall severity for the risk.

```
  Step 1: Identifying a Risk
  Step 2: Factors for Estimating Likelihood
  Step 3: Factors for Estimating Impact
  Step 4: Determining Severity of the Risk
  Step 5: Deciding What to Fix
  Step 6: Customizing Your Risk Rating Model
```

### Step 1: Identifying a Risk
In general, it’s best to err on the side of caution by using the worst-case option, as that will result in the highest overall risk.

### Step 2: Factors for Estimating Likelihood
Note that each factor has a set of options, and each option has a likelihood rating from 0 to 9 associated with it. These numbers will be used later to estimate the overall likelihood.

#### Threat Agent Factors

The first set of factors are related to the threat agent involved. The goal here is to estimate the likelihood of a successful attack by this group of threat agents. Use the worst-case threat agent.

-   **Skill Level** - How technically skilled is this group of threat agents? No technical skills (1), some technical skills (3), advanced computer user (5), network and programming skills (6), security penetration skills (9)
-   **Motive** - How motivated is this group of threat agents to find and exploit this vulnerability? Low or no reward (1), possible reward (4), high reward (9)
-   **Opportunity** - What resources and opportunities are required for this group of threat agents to find and exploit this vulnerability? Full access or expensive resources required (0), special access or resources required (4), some access or resources required (7), no access or resources required (9)
-   **Size** - How large is this group of threat agents? Developers (2), system administrators (2), intranet users (4), partners (5), authenticated users (6), anonymous Internet users (9)

#### Vulnerability Factors

The next set of factors are related to the vulnerability involved. The goal here is to estimate the likelihood of the particular vulnerability involved being discovered and exploited. Assume the threat agent selected above.

-   **Ease of Discovery** - How easy is it for this group of threat agents to discover this vulnerability? Practically impossible (1), difficult (3), easy (7), automated tools available (9)
-   **Ease of Exploit** - How easy is it for this group of threat agents to actually exploit this vulnerability? Theoretical (1), difficult (3), easy (5), automated tools available (9)
-   **Awareness** - How well known is this vulnerability to this group of threat agents? Unknown (1), hidden (4), obvious (6), public knowledge (9)
-   **Intrusion Detection** - How likely is an exploit to be detected? Active detection in application (1), logged and reviewed (3), logged without review (8), not logged (9)

### Step 3: Factors for Estimating Impact
“technical impact”: impact on the application, the data it uses, and the functions it provides.  
“business impact”: impact on the business and company operating the application.

Ultimately, the business impact is more important. However, you may not have access to all the information required to figure out the business consequences of a successful exploit. In this case, providing as much detail about the technical risk will enable the appropriate business representative to make a decision about the business risk.

#### Technical Impact Factors

Technical impact can be broken down into factors aligned with the traditional security areas of concern: confidentiality, integrity, availability, and accountability. The goal is to estimate the magnitude of the impact on the system if the vulnerability were to be exploited.

-   **Loss of Confidentiality** - How much data could be disclosed and how sensitive is it? Minimal non-sensitive data disclosed (2), minimal critical data disclosed (6), extensive non-sensitive data disclosed (6), extensive critical data disclosed (7), all data disclosed (9)
-   **Loss of Integrity** - How much data could be corrupted and how damaged is it? Minimal slightly corrupt data (1), minimal seriously corrupt data (3), extensive slightly corrupt data (5), extensive seriously corrupt data (7), all data totally corrupt (9)
-   **Loss of Availability** - How much service could be lost and how vital is it? Minimal secondary services interrupted (1), minimal primary services interrupted (5), extensive secondary services interrupted (5), extensive primary services interrupted (7), all services completely lost (9)
-   **Loss of Accountability** - Are the threat agents’ actions traceable to an individual? Fully traceable (1), possibly traceable (7), completely anonymous (9)

#### Business Impact Factors
You should be aiming to support your risks with business impact, particularly if your audience is executive level. The business risk is what justifies investment in fixing security problems.

Many companies have an asset classification guide and/or a business impact reference to help formalize what is important to their business. These standards can help you focus on what’s truly important for security. If these aren’t available, then it is necessary to talk with people who understand the business to get their take on what’s important.

-   **Financial damage** - How much financial damage will result from an exploit? Less than the cost to fix the vulnerability (1), minor effect on annual profit (3), significant effect on annual profit (7), bankruptcy (9)
-   **Reputation damage** - Would an exploit result in reputation damage that would harm the business? Minimal damage (1), Loss of major accounts (4), loss of goodwill (5), brand damage (9)
-   **Non-compliance** - How much exposure does non-compliance introduce? Minor violation (2), clear violation (5), high profile violation (7)
-   **Privacy violation** - How much personally identifiable information could be disclosed? One individual (3), hundreds of people (5), thousands of people (7), millions of people (9)

### Step 4: Determining the Severity of the Risk
In this step, the likelihood estimate and the impact estimate are put together to calculate an overall severity for this risk. This is done by figuring out whether the likelihood is low, medium, or high and then do the same for impact. The 0 to 9 scale is split into three parts:
![](/Screenshots/Pasted%20image%2020221218132248.png)

#### Informal Method

In many environments, there is nothing wrong with reviewing the factors and simply capturing the answers. The tester should think through the factors and identify the key “driving” factors that are controlling the result. The tester may discover that their initial impression was wrong by considering aspects of the risk that weren’t obvious.

#### Repeatable Method
If it is necessary to defend the ratings or make them repeatable, then it is necessary to go through a more formal process of rating the factors and calculating the result.

The first step is to select one of the options associated with each factor and enter the associated number in the table. Then simply take the average of the scores to calculate the overall likelihood. For example:
![](/Screenshots/Pasted%20image%2020221218132634.png)

Next, the tester needs to figure out the overall impact. The process is similar here. In many cases the answer will be obvious, but the tester can make an estimate based on the factors, or they can average the scores for each of the factors. Again, less than 3 is low, 3 to less than 6 is medium, and 6 to 9 is high. For example:

![](/Screenshots/Pasted%20image%2020221218132736.png)

#### Determining Severity
However the tester arrives at the likelihood and impact estimates, they can now combine them to get a final severity rating for this risk. Note that if they have good business impact information, they should use that instead of the technical impact information. But if they have no information about the business, then technical impact is the next best thing.
![](/Screenshots/Pasted%20image%2020221218132854.png)In the example above, the likelihood is medium and the technical impact is high, so from a purely technical perspective it appears that the overall severity is high. However, note that the business impact is actually low, so the overall severity is best described as low as well. This is why understanding the business context of the vulnerabilities you are evaluating is so critical to making good risk decisions. Failure to understand this context can lead to the lack of trust between the business and security teams that is present in many organizations.

---


### Step 5: Deciding What to Fix
After the risks to the application have been classified, there will be a prioritized list of what to fix. As a general rule, the most severe risks should be fixed first. It simply doesn’t help the overall risk profile to fix less important risks, even if they’re easy or cheap to fix.

Not all risks are worth fixing, and some loss is not only expected, but justifiable based upon the cost of fixing the issue. For example, if it would cost $100,000 to implement controls to stem $2,000 of fraud per year, it would take 50 years return on investment to stamp out the loss. But remember there may be reputation damage from the fraud that could cost the organization much more.

### Step 6: Customizing the Risk Rating Model
Tailored model is much more likely to produce results that match people’s perceptions about what is a serious risk. A lot of time can be wasted arguing about the risk ratings if they are not supported by a model like this.

#### Adding factors
The tester can choose different factors that better represent what’s important for the specific organization. For example, a military application might add impact factors related to loss of human life or classified information. The tester might also add likelihood factors, such as the window of opportunity for an attacker or encryption algorithm strength.

#### Customizing options

There are some sample options associated with each factor, but the model will be much more effective if the tester customizes these options to the business. For example, use the names of the different teams and the company names for different classifications of information. The tester can also change the scores associated with the options.

#### Weighting factors
The model above assumes that all the factors are equally important. You can weight the factors to emphasize the factors that are more significant for the specific business. This makes the model a bit more complex, as the tester needs to use a weighted average. But otherwise everything works the same.