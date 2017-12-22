from pyFilter.py_filter import PyFilter

if __name__ == "__main__":
    p = PyFilter()
    try:
        p.run()
    except KeyboardInterrupt:
        print("Closing PyFilter")
    finally:
        p.make_persistent(loop=False)  # Save any outstanding bans without the constant loop
        if p.settings["database"] == "sqlite":
            p.database_connection.sqlite_connection.close()
            print("Closed sqlite connection")
