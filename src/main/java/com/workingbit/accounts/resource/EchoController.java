package com.workingbit.accounts.resource;

import com.workingbit.accounts.common.StringMap;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Created by Aleksey Popryaduhin on 16:03 17/06/2017.
 */
@Path("/test")
public class EchoController {

    @GET
    @Path("/echo")
    public Response echo(@QueryParam("echo") String echo) {
        return Response.ok().entity(echo).build();
    }

    @POST
    @Path("/echo")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response echo(StringMap echo) {
        return Response.ok().entity(echo).build();
    }
}
