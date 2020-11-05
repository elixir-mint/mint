ExUnit.start(exclude: Mint.UnixSocketExcludeHelper.exclude(:proxy))
Application.ensure_all_started(:ssl)
Logger.configure(level: :info)
