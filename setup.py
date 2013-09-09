from setuptools import setup

def readme():
    with open('README') as f:
        return f.read()

setup(name='oauth1',
      version='0.4.2',
      description='OAuth 1.0a Provider for Python',
      long_description=readme(),
      keywords='oauth xauth',
      url='https://github.com/tistaharahap/oauth1-provider/',
      author='Batista Harahap',
      author_email='batista@bango29.com',
      license='MIT',
      packages=['oauth1'],
      install_requires=[
          'flask',
          'redis',
          'hiredis',
          'SQLAlchemy'],
      zip_safe=False)