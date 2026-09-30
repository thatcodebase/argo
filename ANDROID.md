### Argo on Android
#### Build with Android Studio on Windows
- Here we are using Android Studio Dolphin 2021.3.1 Patch 1
- Open at the ava\android folder in the source repository.

![android-01.png](/images/android-01.png)

- Android Studio's CMakeLists.txt file is located at android/app/src/main/cpp/CMakeLists.txt  
- Note the following from the Android CMakeLists.txt file.

1. SRC_PATH is set to relatively reference shared source modules at the top level of the repo.
2. Core headers maintained in stm/Core/Inc are reachable by adding a relative path to include_directories.
3. The only Android-specific source module is native-lib.cpp.
4. Core source files are referenced from stm/Core/Src.

![android-02.png](/images/android-02.png)

#### Configure and Debug Argo for Android

- In native-lib.cpp, a simple JSON model is defined for Ava.

![android-03.png](/images/android-03.png)

- Calls to TheDriver().Start() and TheDriver().Stop() are made in the app's MainActivity start and stop methods, respectively.
- Before calling Start(), TheDriver().Model() is called to configure Argo with the model defined above.

![android-04.png](/images/android-04.png)

- The log-path is defined as "data/data/com.davidjwalling.com.ava/files".
- The "files" folder must be created. This can done using the Device File Explorer.
- After creating the folder with write permissions (default), Argo writes its log file.

![android-05.png](/images/android-05.png)

- Double-click on a log file to open it.
- Android loads the *.log file plugin automatically.

![android-06.png](/images/android-06.png)

- Set a breakpoint in Driver::Mainline to trap program execution.

![android-07.png](/images/android-07.png)
