# Intents
## What is an Intent ?

An **[Intent](https://developer.android.com/guide/components/intents-filters.html)** is basically a message that is passed between **[components](https://developer.android.com/guide/components/fundamentals.html#Components)** (such as **Activities**, **Services, Broadcast Receivers,** and **Content Providers**). So, it is almost equivalent to parameters passed to API calls. The fundamental differences between API calls and invoking components via intents are:

-   API calls are synchronous while intent-based invocations are asynchronous.
-   API calls are compile-time binding while intent-based calls are run-time binding.

Of course, Intents can be made to work exactly like API calls by using what are called **explicit intents,** which will be explained later. But more often than not, [**implicit** intents](https://developer.android.com/training/basics/intents/result.html) are the way to go and that is what is explained here.

One component that wants to invoke another has to only express its **intent** to do a job. And any other component that exists and has claimed that it can do such a job through [**intent-filters**](https://developer.android.com/guide/components/intents-filters.html#Receiving), is invoked by the Android platform to accomplish the job. This means, neither components are aware of each other's existence but can still work together to give the desired result for the end-user.

This invisible connection between components is achieved through the combination of intents, intent-filters and the Android platform.

This leads to huge possibilities like:

-   Mix and match or rather plug and play of components at runtime.
-   Replacing the inbuilt Android applications with custom developed applications.
-   Component level reuse within and across applications.
-   Service orientation to the most granular level, if I may say.

Here are additional technical details about [Intents from the Android documentation](https://developer.android.com/reference/android/content/Intent.html).

> An intent is an abstract description of an operation to be performed. It can be used with **startActivity** to launch an **Activity, broadcastIntent** to send it to any interested **BroadcastReceiver** components, and **startService(Intent)** or **bindService(Intent, ServiceConnection, int)** to communicate with a Background Service.
> 
> An Intent provides a facility for performing late runtime binding between the code in different applications. Its most significant use is in the launching of activities, where it can be thought of as the glue between activities. It is basically a passive data structure holding an abstract description of an action to be performed. The primary pieces of information in an intent are:
> 
> -   **action** The general action to be performed, such as ACTION_VIEW, ACTION_EDIT, ACTION_MAIN, etc.
> -   **data** The data to operate on, such as a person record in the contacts database, expressed as a Uri.

Intents are a way of **telling Android what you want to do**. In other words, you describe your intention. Intents can be used to signal to the Android system that a certain event has occurred. Other components in Android can register to this event via an intent filter.

Following are _**2 types of intents**_

## 1.Explicit Intents

used to call a specific component. When you know which component you want to launch and you do not want to give the user free control over which component to use. For example, you have an application that has 2 activities. Activity A and activity B. You want to launch activity B from activity A. In this case you define an explicit intent targeting activityB and then use it to directly call it.

## 2.Implicit Intents

used when you have an idea of what you want to do, but you do not know which component should be launched. Or if you want to give the user an option to choose between a list of components to use. If these Intents are send to the Android system it searches for all components which are registered for the specific action and the data type. If only one component is found, Android starts the component directly. For example, you have an application that uses the camera to take photos. One of the features of your application is that you give the user the possibility to send the photos he has taken. You do not know what kind of application the user has that can send photos, and you also want to give the user an option to choose which external application to use if he has more than one. In this case you would not use an explicit intent. Instead you should use an implicit intent that has its action set to ACTION_SEND and its data extra set to the URI of the photo.

An explicit intent is always delivered to its target, no matter what it contains; the filter is not consulted. But an implicit intent is delivered to a component only if it can pass through one of the component's filters

## Intent Filters

If an Intents is send to the Android system, it will determine suitable applications for this Intents. If several components have been registered for this type of Intents, Android offers the user the choice to open one of them.

This determination is based on IntentFilters. An IntentFilters specifies the types of Intent that an activity, service, orBroadcast Receiver can respond to. An Intent Filter declares the capabilities of a component. It specifies what anactivity or service can do and what types of broadcasts a Receiver can handle. It allows the corresponding component to receive Intents of the declared type. IntentFilters are typically defined via the AndroidManifest.xml file. For BroadcastReceiver it is also possible to define them in coding. An IntentFilters is defined by its category, action and data filters. It can also contain additional metadata.

If a component does not define an Intent filter, it can only be called by explicit Intents.

Following are _**2 ways to define a filter**_

## 1.Manifest file

If you define the intent filter in the manifest, your application does not have to be running to react to the intents defined in it’s filter. Android registers the filter when your application gets installed.

## 2.BroadCast Receiver

If you want your _broadcast receiver_ to receive the intent only when your application is running. Then you should define your intent filter during run time (programatically). Keep in mind that this works for broadcast receivers only.


Source: 
[What is an Intent in Android?](https://stackoverflow.com/questions/6578051/what-is-an-intent-in-android)
[Android Intents - Tutorial](https://www.vogella.com/tutorials/AndroidIntent/article.html)