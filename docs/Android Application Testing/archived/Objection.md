# Tutorial
[Sharpening your FRIDA scripting skills with Frida Tool (securelayer7.net)](https://blog.securelayer7.net/sharpening-your-frida-scripting-skills-with-frida-tool/)


# Code Snippets
```bash
# Start objection
objection -g uk.rossmarks.fridalab explore 

# Watch the function calls of a class
android hooking watch class uk.rossmarks.fridalab.MainActivity

# Modify return value of a method
android hooking set return_value uk.rossmarks.fandroid hooking watch class uk.rossmarks.fridalab.MainActivity
```