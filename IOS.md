# Argo on iOS
- Here we are using an 11" 3rd-Generation iPad Pro model MHQR3LL/A.
- The Wi-Fi is configured as "Automatic", that is, with DHCP enabled.
- The assigned IP address, subnetwork mask and Gateway ("Router") addresses are shown.

![ios-05.png](/images/ios-05.png)

- Here we are using Xcode Version 14.0.1 (14A400) on macOS Monterey Version 12.6.2 to debug Argo on the iPad.
- Open the project argo.xcodeproj in the ios/argo folder of the repository.

![ios-06.png](/images/ios-06.png)

- Xcode will locate cJSON.c and cJSON.h even though they are located in stm/Core/Src and Inc, respectively, as long we these files are added to the project as shown.
- Objective-C prefers a pointer to a reference, so we've added TheDriverPtr() to return an IDriver*.
- We set Argo's title, copyright, name and model before calling Start().
- Set a breakpoint in wrap_driver.mm at the call to Driver::Start().

![ios-01.png](/images/ios-01.png)

- Click the right arrow icon to start the debugger.
- Use the Debug > View Debugging > Take Screenshot menu option to capture the iPad screen.
- The SwiftUI app displays a green "Start" and a red "Stop" button.

![ios-02.png](/images/ios-02.png)

- Touch the green "Start" button on the iPad to invoke the wrap_driver start() method.
- The contents of the Driver instance can be seen.

![ios-03.png](/images/ios-03.png)

- Set a breakpoint in Channel::HaveDiscoRequest to inspect the reply about to be written.
- Disable the break point and continue program execution.

![ios-04.png](/images/ios-04.png)

- We use a network traffic monitor, Wireshark, to confirm traffic sent from and to Argo on the iPad.

![ios-07.png](/images/ios-07.png)



