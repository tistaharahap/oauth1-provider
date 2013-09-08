from setuptools import setup

def readme():
    with open('README') as f:
        return f.read()

setup(name='oauth1',
      version='0.4.0',
      description='OAuth 1.0 Provider with Redis in Python',
      long_description=readme(),
      keywords='oauth redis xauth',
      url='https://github.com/tistaharahap/oauth1-provider-redis-py/',
      author='Batista Harahap',
      author_email='batista@bango29.com',
      license='MIT',
      packages=['oauth1'],
      install_requires=[
          'flask',
          'redis',
          'hiredis'],
      zip_safe=False)