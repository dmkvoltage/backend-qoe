"""
Comprehensive Database Connection Checker
Run this script to verify your PostgreSQL database connection and troubleshoot issues
"""
import os
import sys
from datetime import datetime
from dotenv import load_dotenv
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import SQLAlchemyError
import psycopg2
from psycopg2 import sql

# Load environment variables
load_dotenv()

def check_environment_variables():
    """Check if all required environment variables are set"""
    print("🔍 Checking Environment Variables...")
    
    env_vars = [
        "SUPABASE_DATABASE_URL",
        "DATABASE_URL",
        "SECRET_KEY"
    ]
    
    found_vars = {}
    for var in env_vars:
        value = os.getenv(var)
        if value:
            # Mask sensitive parts of the URL
            if "postgresql://" in value:
                masked = value[:20] + "***" + value[-20:] if len(value) > 40 else "***"
                found_vars[var] = masked
            else:
                found_vars[var] = value[:10] + "***" if len(value) > 10 else "***"
        else:
            found_vars[var] = "❌ NOT SET"
    
    for var, value in found_vars.items():
        print(f"  {var}: {value}")
    
    return found_vars

def test_direct_connection():
    """Test direct connection using psycopg2"""
    print("\n🔗 Testing Direct PostgreSQL Connection...")
    
    # Your confirmed connection details
    connection_params = {
        "host": "aws-0-sa-east-1.pooler.supabase.com",
        "port": 6543,
        "database": "postgres",
        "user": "postgres.tlcbimopgpcaxgehncey",
        "password": "08200108dyekrane"
    }
    
    try:
        print(f"  Connecting to: {connection_params['host']}:{connection_params['port']}")
        print(f"  Database: {connection_params['database']}")
        print(f"  User: {connection_params['user']}")
        
        conn = psycopg2.connect(**connection_params)
        cursor = conn.cursor()
        
        # Test basic query
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        print(f"✅ Direct connection successful!")
        print(f"  PostgreSQL version: {version}")
        
        # Test permissions
        cursor.execute("SELECT current_user, current_database();")
        user, db = cursor.fetchone()
        print(f"  Current user: {user}")
        print(f"  Current database: {db}")
        
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Direct connection failed: {e}")
        return False

def test_sqlalchemy_connection():
    """Test SQLAlchemy connection"""
    print("\n🔧 Testing SQLAlchemy Connection...")
    
    # Test multiple connection strings
    connection_strings = [
        os.getenv("SUPABASE_DATABASE_URL"),
        os.getenv("DATABASE_URL"),
        "postgresql://postgres.tlcbimopgpcaxgehncey:08200108dyekrane@aws-0-sa-east-1.pooler.supabase.com:6543/postgres"
    ]
    
    # Filter out None values
    connection_strings = [url for url in connection_strings if url]
    
    for i, url in enumerate(connection_strings):
        try:
            print(f"\n  Testing connection string {i+1}:")
            print(f"  URL: {url[:50]}...")
            
            engine = create_engine(
                url,
                pool_pre_ping=True,
                pool_recycle=300,
                pool_size=2,
                max_overflow=5,
                echo=False,
                connect_args={"connect_timeout": 10}
            )
            
            # Test connection
            with engine.connect() as conn:
                result = conn.execute(text("SELECT 1 as test"))
                test_value = result.fetchone()[0]
                print(f"✅ SQLAlchemy connection {i+1} successful! Test query returned: {test_value}")
                
                # Get database info
                result = conn.execute(text("SELECT current_database(), current_user, version()"))
                db_name, user, version = result.fetchone()
                print(f"  Database: {db_name}")
                print(f"  User: {user}")
                print(f"  Version: {version[:50]}...")
                
                return engine, url
                
        except Exception as e:
            print(f"❌ SQLAlchemy connection {i+1} failed: {e}")
            continue
    
    return None, None

def check_tables(engine):
    """Check if required tables exist"""
    print("\n📋 Checking Database Tables...")
    
    try:
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        
        print(f"  Found {len(existing_tables)} tables:")
        for table in existing_tables:
            print(f"    - {table}")
        
        # Check for our required tables
        required_tables = ["users", "feedback", "network_logs"]
        missing_tables = [table for table in required_tables if table not in existing_tables]
        
        if missing_tables:
            print(f"\n⚠️ Missing required tables: {missing_tables}")
            return False
        else:
            print(f"\n✅ All required tables exist!")
            return True
            
    except Exception as e:
        print(f"❌ Error checking tables: {e}")
        return False

def check_table_structure(engine):
    """Check table structure and columns"""
    print("\n🏗️ Checking Table Structure...")
    
    try:
        inspector = inspect(engine)
        
        tables_to_check = ["users", "feedback", "network_logs"]
        
        for table_name in tables_to_check:
            if table_name in inspector.get_table_names():
                print(f"\n  📊 Table: {table_name}")
                columns = inspector.get_columns(table_name)
                
                for col in columns:
                    nullable = "NULL" if col['nullable'] else "NOT NULL"
                    default = f" DEFAULT {col['default']}" if col['default'] else ""
                    print(f"    - {col['name']}: {col['type']} {nullable}{default}")
            else:
                print(f"\n  ❌ Table {table_name} does not exist")
                
    except Exception as e:
        print(f"❌ Error checking table structure: {e}")

def test_data_operations(engine):
    """Test basic data operations"""
    print("\n💾 Testing Data Operations...")
    
    try:
        with engine.connect() as conn:
            # Test INSERT
            print("  Testing INSERT operation...")
            insert_query = text("""
                INSERT INTO network_logs (
                    user_id, carrier, network_type, signal_strength, 
                    download_speed, upload_speed, latency, location
                ) VALUES (
                    1, 'TEST_CARRIER', 'TEST_TYPE', -50, 
                    10.5, 5.2, 20, 'TEST_LOCATION'
                ) RETURNING id
            """)
            
            result = conn.execute(insert_query)
            new_id = result.fetchone()[0]
            print(f"✅ INSERT successful! New record ID: {new_id}")
            
            # Test SELECT
            print("  Testing SELECT operation...")
            select_query = text("SELECT * FROM network_logs WHERE id = :id")
            result = conn.execute(select_query, {"id": new_id})
            record = result.fetchone()
            print(f"✅ SELECT successful! Retrieved record: {record}")
            
            # Test DELETE (cleanup)
            print("  Cleaning up test data...")
            delete_query = text("DELETE FROM network_logs WHERE id = :id")
            conn.execute(delete_query, {"id": new_id})
            conn.commit()
            print("✅ Test data cleaned up")
            
            return True
            
    except Exception as e:
        print(f"❌ Data operations test failed: {e}")
        return False

def main():
    """Main database checker function"""
    print("🚀 PostgreSQL Database Connection Checker")
    print("=" * 50)
    print(f"Timestamp: {datetime.now()}")
    
    # Step 1: Check environment variables
    env_vars = check_environment_variables()
    
    # Step 2: Test direct connection
    direct_success = test_direct_connection()
    
    # Step 3: Test SQLAlchemy connection
    engine, working_url = test_sqlalchemy_connection()
    
    if engine:
        # Step 4: Check tables
        tables_exist = check_tables(engine)
        
        # Step 5: Check table structure
        check_table_structure(engine)
        
        # Step 6: Test data operations
        if tables_exist:
            data_ops_success = test_data_operations(engine)
        else:
            print("\n⚠️ Skipping data operations test - missing tables")
            data_ops_success = False
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 SUMMARY")
        print("=" * 50)
        print(f"Direct Connection: {'✅ SUCCESS' if direct_success else '❌ FAILED'}")
        print(f"SQLAlchemy Connection: {'✅ SUCCESS' if engine else '❌ FAILED'}")
        print(f"Required Tables: {'✅ EXIST' if tables_exist else '❌ MISSING'}")
        print(f"Data Operations: {'✅ SUCCESS' if data_ops_success else '❌ FAILED'}")
        
        if working_url:
            print(f"\nWorking connection string: {working_url[:50]}...")
        
        if direct_success and engine and tables_exist and data_ops_success:
            print("\n🎉 DATABASE IS FULLY FUNCTIONAL!")
        else:
            print("\n⚠️ DATABASE HAS ISSUES - CHECK ERRORS ABOVE")
            
    else:
        print("\n❌ CANNOT CONNECT TO DATABASE")
        print("Please check your connection details and try again.")

if __name__ == "__main__":
    main()
