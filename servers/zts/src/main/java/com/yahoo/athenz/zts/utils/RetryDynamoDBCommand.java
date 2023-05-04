package com.yahoo.athenz.zts.utils;

import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughputExceededException;
import com.yahoo.athenz.zts.ZTSConsts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

public class RetryDynamoDBCommand<T> {
    private final int dynamodbMaxRetries = Integer.parseInt(
            System.getProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_RETRIES, "10"));

    private final Long dynamodbRetriesSleepMillis = Long.parseLong(
            System.getProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_RETRIES_SLEEP_MILLIS, "1000"));

    private static final Logger LOGGER = LoggerFactory.getLogger(RetryDynamoDBCommand.class);

    // Takes a function and executes it, if fails, passes the function to the retry command
    public T run(Supplier<T> function) throws TimeoutException, InterruptedException {
        try {
            return function.get();
        } catch (ProvisionedThroughputExceededException e) {
            return retry(function);
        }
    }

    private T retry(Supplier<T> function) throws InterruptedException, TimeoutException {
        for (int retryNumber = 1; retryNumber <= dynamodbMaxRetries; ++retryNumber) {
            try {
                return function.get();
            } catch (ProvisionedThroughputExceededException ex) {
                LOGGER.debug("{} retry out of {} retries in {} milliseconds",
                        retryNumber, dynamodbMaxRetries, dynamodbRetriesSleepMillis);
                Thread.sleep(dynamodbRetriesSleepMillis);
            }
        }

        throw new TimeoutException("Failed too many retries. Check table provisioned throughput settings.");
    }
}
