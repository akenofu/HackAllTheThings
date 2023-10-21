# Frida
# Frida CLI commands
```bash
# -U : USB
# -l : Load Script
# -f : Spanws a package
frida -U -l callme.js -f com.ironhackers.androidlab

# No -f implies u are attaching to process, process name no need to specify package name only the last part is required
frida -U -l callme.js androidlab
```

# Basics
```js
// Returns the class itself and not instances of the class
Java.use()

// Returns each instance of the class found to perform some operation on it
Java.choose()
```

# Android Snippets
## Call a function
```js
Java.perform(function (){

    Java.choose('com.ironhackers.androidlab.Callme', {

        onMatch:  ( instance) => {

            Java.scheduleOnMainThread( () => {

                instance.call_me_win();

            })

        },

        onComplete: () => {}

    })

});
```

## Modify a function implementation
```js
Java.perform(function(){

    var alwaystrueactivity= Java.use('com.ironhackers.androidlab.Alwaystrue');

    alwaystrueactivity.impossible_check.implementation = function () {

       return true;

       }

   });
```

## Create an Object of a class and setting the property value of a class
```js
Java.perform(() => {

    var walletClass = Java.use('com.ironhackers.androidlab.Wallet');

    Java.choose('com.ironhackers.androidlab.Createme', {

        onMatch: (instance) => {

            var y = instance.person

            instance.person.value.setWallet(walletClass.$new(100))

        },

        onComplete: () => {

        }

    })  

})
```

## Inspect Arguments of a function

N.B. don't use function arrows when modifying the implementation of a function as you lose access to the this keyword. This means you can no loger do `this.originalFunction(arg0, arg1)` to call the original implementation of the function.

```js
Java.perform( () => {

    Java.choose('com.ironhackers.androidlab.Sniff', {

        onMatch: (instance) => {

            instance.generateFlag.implementation = function(arg0, arg1) {

                console.log(arg1)

                this.generateFlag(arg0,arg1)

            }

        },

        onComplete: () => {}

    })

})
```

## Pin Brute Force
```js
'use strict'

if (Java.available) {

    Java.perform(function() {

        Java.choose('uk.rossmarks.fridalab.MainActivity', {

            onMatch: function(instance){

                var pinFunc = Java.use('uk.rossmarks.fridalab.challenge_07');

                var correctPin = ''

                for(var i = 0 ; i < 10000; i++){

                    if(pinFunc.check07Pin(i.toString().padStart(4)) == true){

                        correctPin = i;

                        console.log('The correct pin is: ' + i)

                        break;

                    }

                }

                instance.chall07(correctPin.toString())

            },

            onComplete: function() {

  

            }

        })

  

    })  

  

}

else {

    console.log('[-] Java is not available')

}
```

## Change Text on A Button (UI Manipulation)
```js
'use strict'
if (Java.available) {

    Java.perform(function () {

        Java.choose('uk.rossmarks.fridalab.MainActivity', {

            onMatch: function(instance) {

                var buttonClass = Java.use('android.widget.Button')

                var checkID = instance.findViewById(2131165231)

                var checkButton = Java.cast(checkID, buttonClass)

                var javaString = Java.use('java.lang.String')

                checkButton.setText(javaString.$new('Confirm'))

            },

            onComplete: function(){

  

            }

        })

    })

  

}

else {

    console.log('[-] Java is not available')

}
```


## Spoof function call if it matches a class name
```js
Java.perform(function() {
    let RichClientUtilitiesImpl = Java.use("fake.bank.data.richclient.RichClientUtilitiesImpl");
    let ValidatePinClass = Java.use("fake.bank.data.richclient.domainservice.ValidatePin$Request")
    RichClientUtilitiesImpl["encryptAndSignPayload"].implementation = function (t, iv, sessionKey, keyStoreAlias, requestClass, tuples) {
    console.log(ValidatePinClass.$className == t.$className)
    if(t.$className == ValidatePinClass.$className)
    {
        t = ValidatePinClass.$new('1337', '14142c7b-5134-1456-758c-268ca60dafd5', 'yQY3z300uLRC7fTW0=')
        console.log("Spoofed!")
    }
    console.log(`RichClientUtilitiesImpl.encryptAndSignPayload is called: t=${t}, iv=${iv}, sessionKey=${sessionKey}, keyStoreAlias=${keyStoreAlias}, requestClass=${requestClass}, tuples=${tuples}`);
    let result = this["encryptAndSignPayload"](t, iv, sessionKey, keyStoreAlias, requestClass, tuples);
    return result;
};


let RichClientProfile = Java.use("fake.bank.data.richclient.model.RichClientProfile");
RichClientProfile["getDeviceID"].implementation = function () {
    let result = this["getDeviceID"]();
    let spoofedResult =  '9069ac10-4214-4fbd-1514-9a3c6c1d1242'
    // console.log(`RichClientProfile.getDeviceID result=${result}`);
    return result;
};

});
```
# Tools built on top of Frida
- Objection
- [GitHub - Ch0pin/medusa: Binary instrumentation framework based on FRIDA](https://github.com/Ch0pin/medusa)
# Resources
[Frida - Python bindings and intercommunication for Android Testing](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting/frida-tutorial/frida-tutorial-2#python-1)
[Frida Tutorial - HackTricks](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting/frida-tutorial)
[Sharpening your FRIDA scripting skills with Frida Tool (securelayer7.net)](https://blog.securelayer7.net/sharpening-your-frida-scripting-skills-with-frida-tool/)