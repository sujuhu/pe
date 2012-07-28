#include <iostream>

#include <cppunit/TestRunner.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/BriefTestProgressListener.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <filemap.h>

class SAMPLE_87f6447ba9b75486969b59e1c911ac72 : public CPPUNIT_NS::TestCase
{
	CPPUNIT_TEST_SUITE(SAMPLE_87f6447ba9b75486969b59e1c911ac72);
	CPPUNIT_TEST(testHello);
	CPPUNIT_TEST(testWorld);
	CPPUNIT_TEST_SUITE_END();
 
public:
	void setUp(void) {}
	void tearDown(void) {} 
 
protected:
	void testHello(void) {;}
	void testWorld(void) {;}
};

class SAMPLE_0c94b325dca948dcdf81036a5306901b : public CPPUNIT_NS::TestCase
{
	CPPUNIT_TEST_SUITE(SAMPLE_0c94b325dca948dcdf81036a5306901b);
	CPPUNIT_TEST(testHello);
	CPPUNIT_TEST(testWorld);
	CPPUNIT_TEST_SUITE_END();
 
public:
	void setUp(void) {}
	void tearDown(void) {} 
 
protected:
	void testHello(void) {;}
	void testWorld(void) {;}
};
 
CPPUNIT_TEST_SUITE_REGISTRATION(SAMPLE_87f6447ba9b75486969b59e1c911ac72);
CPPUNIT_TEST_SUITE_REGISTRATION(SAMPLE_0c94b325dca948dcdf81036a5306901b);
int main( int argc, char **argv )
{
   // Create the event manager and test controller
   CPPUNIT_NS::TestResult controller;
 
   // Add a listener that colllects test result
   CPPUNIT_NS::TestResultCollector result;
   controller.addListener( &result );        
 
   // Add a listener that print dots as test run.
   CPPUNIT_NS::BriefTestProgressListener progress;
   controller.addListener( &progress );      
 
   // Add the top suite to the test runner
   CPPUNIT_NS::TestRunner runner;
   runner.addTest( CPPUNIT_NS::TestFactoryRegistry::getRegistry().makeTest() );
   runner.run( controller );
 
   return result.wasSuccessful() ? 0 : 1;
}