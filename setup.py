import setuptools

setuptools.setup(
	name = "TP-OOB-Interaction",
	version = "2024.10.1",
	author = "TP Cyber Security",
	license = "MIT",
	author_email = "tpcybersec2023@gmail.com",
	description = "Get OOB interactions from Interactsh and send to Discord, Telegram, Slack",
	long_description = open("README.md").read(),
	long_description_content_type = "text/markdown",
	install_requires = open("requirements.txt").read().split(),
	url = "https://github.com/truocphan/TP-OOB-Interaction",
	packages = setuptools.find_packages(),
	classifiers = [
		"Programming Language :: Python :: 3"
	],
	entry_points = {
		"console_scripts": [
			"TP-OOB-Interaction = TP_OOB_Interaction:main"
		]
	},
)