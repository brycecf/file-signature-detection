from setuptools import setup, find_packages

setup(
    description="CLI for determining file types based on file headers (and trailers).",
    entry_points={
        "console_scripts": [
            "file-signature-detection = file_signature_detection.cli:cli"
        ]
    },
    python_requires='>=3.6',
    name="file_signature_detection",
    packages=find_packages(),
    version=0.1,
    zip_safe=True,
    install_requires=["click", "pygtrie"],
    package_data={"file_signature_detection": ["data/*.txt"]},
)
