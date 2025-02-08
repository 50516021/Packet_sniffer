# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html


"""
command to generate documentation:
    sphinx-apidoc -f -o ./source ../
    make make latexpdf
"""
import os
import sys
sys.path.insert(0, os.path.abspath('../../'))
sys.path.insert(1, os.path.abspath('../../modules/'))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'PacketAnalyser'
copyright = '2025, Akira Takeuchi'
author = 'Akira Takeuchi'
release = '1.0.0'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'myst_parser'
]

templates_path = ['_templates']
exclude_patterns = []
html_extra_path = ['extra']


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']
