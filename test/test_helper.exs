ExUnit.start(exclude: [:proxy, :skip])
Application.ensure_all_started(:ssl)
Logger.configure(level: :info)
