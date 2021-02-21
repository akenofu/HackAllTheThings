## Data Storage

#### Identify Storage Mechanisms used by the application ? 
- Does application store data on SDCard
- Are encryptian keys hardcoded ?
- is the Key Derivation Function(KDF) accessible for us ? 
	- Does the app user predictable identifiers
		- Password reusability
		- Weak and predictable
		- Identifiers which are accessible to other applications 
- Are the keys stored publicly ?
- Does the application/algorithm zero out passwords stored in memory

***

#### Is sensitive data stored in Process Memory
- Are secerets zero'd out after being used
	- does the compilter optimize the code and remove the zero'ing operation ?
- Are immutable data-types used to store secerets ? (They store data on heap)
- Are complex data-types used to store secerets ? 

***