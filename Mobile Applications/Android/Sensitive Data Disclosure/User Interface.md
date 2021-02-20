- Check AndroidManifest.xml to make sure input fields are masked password
		`android:inputType="textPassword"`
- Check that `FLAG_SECURE` has been set for important windows
	   ```Java
		getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
						WindowManager.LayoutParams.FLAG_SECURE);

		setContentView(R.layout.activity_main);
		
		
- To exploit checkout https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05d-testing-data-storage#dynamic-analysis-7

