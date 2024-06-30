ExUnit.start(exclude: [:integration, :proxy])
Application.ensure_all_started(:ssl)
Logger.configure(level: :info)

Mox.defmock(TransportMock, for: Mint.Core.Transport)
