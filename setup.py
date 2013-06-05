from setuptools import setup

def readme():
    with open('README.md') as f:
        return f.read()

setup(name='oauth1-provider',
      version='0.2.0',
      description='OAuth 1.0 Provider with Redis in Python',
      long_description=readme(),
      keywords='oauth redis xauth',
      url='https://github.com/tistaharahap/oauth1-provider-redis-py/',
      author='Batista Harahap',
      author_email='batista@bango29.com',
      license='MIT',
      packages=['oauth1-provider'],
      install_requires=[
          'flask',
          'redis'],
      zip_safe=False)