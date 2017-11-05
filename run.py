from pyFilter.py_filter import PyFilter

if "__main__" == __name__:
    p = PyFilter()
    try:
        p.run()
    finally:
        if p.settings["database"] == "sqlite":
            p.database_connection.sqlite_connection.close()
            print("Closed sqlite connection")
