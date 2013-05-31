from setuptools import setup

def readme():
    with open('README') as f:
        return f.read()

setup(name='oauth1-provider',
      version='0.1.0',
      description='OAuth 1.0a Provider with Redis in Python',
      long_description=readme(),
      keywords='oauth 1.0a redis xauth',
      url='https://github.com/tistaharahap/oauth1-provider-redis-py/',
      author='Batista Harahap',
      author_email='batista@bango29.com',
      license='MIT',
      packages=['oauth1-provider'],
      install_requires=[
          'flask',
          'redis'],
      zip_safe=False)