# Argo on FreeRTOS

### Install ST Micro STM32 Cube IDE

STM32CubeIDE is the development environment used here for building argo for the ST Micro Nucleo F767 development board. This page provides instructions for downloading, installing and configuring STM32CubeIDE on Windows 10.

Navigate to [https://st.com/en/development-tools/stm32cubeide.html](https://st.com/en/development-tools/stm32cubeide.html).
Scroll down to the "Get Software" section of this page.
If you're prompted to login or register, either enter your ST.com credentials or register.
At the time of this writing, there is no cost for registering, other than providing a valid email address.

![stm32-1.7.0-01.png](/images/stm32-1.7.0-01.png)

We're going to install and use STM32 Cube IDE version 1.7.0.
Use the "Select verion" drop-down to select this version.

![stm32-1.7.0-02.png](/images/stm32-1.7.0-02.png)

As of this writing, the downloaded installer name for STM32 Cube IDE version 1.7.0 is st-stm32cubeide_1.7.0_10852_20210715_0634_x86_64.exe.zip. Unzip the archived installer executable and run the installer executable.
If prompted by Windows 10 whether to allow the installer to make changes to the system, click "Yes".

![stm32-1.7.0-03.png](/images/stm32-1.7.0-03.png)

On the installer "Welcome" page, click "Next".

![stm32-1.7.0-04.png](/images/stm32-1.7.0-04.png)

On the installer "License Agreement" page, click "I Agree".

![stm32-1.7.0-05.png](/images/stm32-1.7.0-05.png)

On the installer "Choose Install Location" page, here we accept the default location and click "Next".

![stm32-1.7.0-06.png](/images/stm32-1.7.0-06.png)

On the installer "Choose Components" page, uncheck "SEGGER J-Link drivers" and leave checked "ST-LINK drivers" and click "Install".

![stm32-1.7.0-07.png](/images/stm32-1.7.0-07.png)

When the installation completes and the installer "Installation Complete" page is displayed, click "Next".

![stm32-1.7.0-08.png](/images/stm32-1.7.0-08.png)

On the installer "Completing" page, leave the "Create desktop shortcut" checked if you want the installer to create a desktop icon for the STM32CubeIDE program. Otherwise, uncheck the check box. Then click "Finish".

## Configure the F767ZITx board

### Set the Clock Configuration

- Open the stm.ioc file in STM32 Cube IDE.
- Select the "Clock Configuration" tab.
- Set the HCLK to 216 MHz.
- Set the System CLock Mux radio button to PLLCLK.
- Set the USART3 Clock Mux to SYSCLK and 216 MHz.
- Set the PLL Source Mux to HSE.

![stm32-1.7.0-13.png](/images/stm32-1.7.0-13.png)

### Set the RCC Mode and Configuration

- Select the "Pinout & Configuration" tab.
- Select the "System Core" category.
- Select the "RCC" section.
- Set both the High Speed Clock and Low Speed Clock to "Crystal/Ceramic Resonator".

![stm32-1.7.0-15.png](/images/stm32-1.7.0-15.png)

### Set the SYS Mode and Configuration

- Select the "SYS" section.
- Set the Debug to "Serial Wire".
- Set the Timebase Source to "TIM6".

![stm32-1.7.0-16.png](/images/stm32-1.7.0-16.png)

### Set the ETH Mode and Configuration

- Select the "Connectivity" category.
- Select the "ETH" section.
- Set the Mode to "RMII".
- On the GPIO tab, Confirm there are GPIO settings for all Ethernet pins.

![stm32-1.7.0-17.png](/images/stm32-1.7.0-17.png)

### Set the USART3 Mode and Configuration

- Select the "USART3" section.
- Set the Mode to "Asynchronous".
- Set the "Hardware Flow Control (RS232)" to "Disable".
- On the "Parameter Settings" tab,
- Set the Baud Rate to "115200 Bits/s"
- Set the Word Length to "8 Bits (including Parity)".
- Set the Parity to "None".
- Set the Stop Bits to "1".

![stm32-1.7.0-18.png](/images/stm32-1.7.0-18.png)

- On the "GPIO Settings" tab, confirm pin settings for USART3_TX and USART3_RX.

![stm32-1.7.0-19.png](/images/stm32-1.7.0-19.png)

### Set the FREERTOS Mode and Configuration

- Select the "Middleware" category.
- Select the "FREERTOS" section.
- Set the Interface to "CMSIS_V2".
- On the "Config parameters" tab,
- Set the "MINIMAL_STACK_SIZE" to "128 Words".
- Set the "TOTAL_HEAP_SIZE" to "262144 Bytes".
- Set the "TIMER_TASK_STACK_DEPTH" to "256 Words".
- Set the "USE_POSIX_ERRNO" to "Enabled".

![stm32-1.7.0-20.png](/images/stm32-1.7.0-20.png)

- On the "Advanced settings" tab,
- Set the "USE_NEWLIB_REENTRANT" to "Enabled".

![stm32-1.7.0-21.png](/images/stm32-1.7.0-21.png)

- On the "Tasks and Queues" tab,
- Set the "defaultTask" Stack Size to "256".

![stm32-1.7.0-22.png](/images/stm32-1.7.0-22.png)

- On the "Timers and Semaphores" tab,
- Create "myBinarySem01" as Allocation "Dynamic".

![stm32-1.7.0-23.png](/images/stm32-1.7.0-23.png)

- On the "Mutexes" tab,
- Create "myMutex01" as Allocation "Dynamic".

![stm32-1.7.0-24.png](/images/stm32-1.7.0-24.png)

### Set the LWIP Mode and Configuration

- Select the "LWIP" section.
- Set the Mode th "Enabled".
- On the "General Settings" tab,
- Set "LWIP_DHCP" to "Disabled".
- Set "IP_ADDRESS", "NETMASK_ADDRESS", and "GATEWAY_ADDRESS" to appropriate values for your network.

![stm32-1.7.0-25.png](/images/stm32-1.7.0-25.png)

### Confirm the System Core GPIO Settings

- Select the GPIO section.
- On the GPIO tab, confirm GPIO pin assignments for the Green, Blue and Red LEDs.
- On the ETH tab, confirm GPIO pin assignments for Ethernet.
- On the USART tab, confirm GPIO pin assignments for USART3_TX and USART3_RX.
- If these pin assignments are not present, check again after the following instructions.

![stm32-1.7.0-14.png](/images/stm32-1.7.0-14.png)

Save the stm.ioc file.
