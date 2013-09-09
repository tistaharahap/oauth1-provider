from setuptools import setup

setup(name='oauth1-provider',
      version='0.4.10',
      description='OAuth 1.0a Provider for Python',
      long_description='Initiallly focused in leveraging performance by using Redis as the primary OAuth Provider backend, user authentications can be handled differently using any other databases. Now SQLAlchemy support is added.',
      keywords='oauth xauth provider',
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