{ lib
, buildPythonPackage
, fetchPypi
, pyroute2-core
, pythonOlder
}:

buildPythonPackage rec {
  pname = "pyroute2-ndb";
  version = "0.6.10";
  format = "setuptools";

  disabled = pythonOlder "3.7";

  src = fetchPypi {
    pname = "pyroute2.ndb";
    inherit version;
    hash = "sha256-kjgeA7PV6JLvCvaZxe4y984wTo8ExU7Yf1Wr+7jNwu4=";
  };

  propagatedBuildInputs = [
    pyroute2-core
  ];

  # pyroute2 sub-modules have no tests
  doCheck = false;

  pythonImportsCheck = [
    "pr2modules.ndb"
  ];

  meta = with lib; {
    description = "NDB module for pyroute2";
    homepage = "https://github.com/svinota/pyroute2";
    license = licenses.asl20;
    maintainers = with maintainers; [ fab ];
    platforms = platforms.unix;
  };
}
